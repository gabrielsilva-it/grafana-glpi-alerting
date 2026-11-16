#!/usr/bin/env python3
"""
grafana_glpi_webhook.py - Grafana alerting -> GLPI service desk bridge.

Receives Grafana webhook notifications and manages GLPI tickets per site/incident:
  * one ticket per site while any symptom is active; new symptoms become follow-ups;
  * when every symptom of the site recovers, the ticket gets a solution and is closed
    (technician and location are filled in first, because GLPI requires them);
  * if the problem comes back within REOPEN_WINDOW_MINUTES the same ticket is reopened;
  * "flood" detection: many sites failing at once = one emergency ticket, not N tickets;
  * hub-and-spoke tunnel correlation: tunnel alerts from many branches become follow-ups
    of the HQ link ticket instead of one ticket per branch;
  * non-network sources (ERP, BACKUP, INFRA) never take part in flood/tunnel logic.

Configuration comes from environment variables (see README) and an optional sites JSON file.
"""

import json
import logging
import os
import re
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path

import requests
from flask import Flask, request, jsonify

# ---------------------------------------------------------------------------
# CONFIGURAÇÃO — ajuste estes valores
# ---------------------------------------------------------------------------
GLPI_URL = os.environ.get("GLPI_URL", "http://glpi.example.com/apirest.php")
GLPI_APP_TOKEN = os.environ.get("GLPI_APP_TOKEN", "")
GLPI_USER_TOKEN = os.environ.get("GLPI_USER_TOKEN", "")
GLPI_ENTITY_ID = int(os.environ.get("GLPI_ENTITY_ID", "0"))          # 0 = root entity
GLPI_CATEGORY_ID = int(os.environ.get("GLPI_CATEGORY_ID", "0"))      # default ITIL category (0 = none)
GLPI_GROUP_ID = int(os.environ.get("GLPI_GROUP_ID", "0"))            # technician group assigned on creation
GLPI_REQUESTER_ID = int(os.environ.get("GLPI_REQUESTER_ID", "0"))    # requester user (usually the API account)

EMAIL_ENABLED = False


def _load_sites() -> dict:
    """Site -> GLPI location id. Read from SITES_FILE (JSON) when set; the default is only an example."""
    path = os.environ.get("SITES_FILE")
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return {k.upper(): int(v) for k, v in json.load(f).items()}
    return {
        "HQ": 2,
        "BRANCH01": 3,
        "BRANCH02": 4,
        "BRANCH03": 5,
        "HQ_SWITCHES": 2,   # core switches at HQ
        "ERP": 2,           # ERP server (at HQ)
        "BACKUP": 2,        # Proxmox backup failures
        "INFRA": 2,         # Proxmox infrastructure
    }


SITE_TO_LOCATION_ID = _load_sites()

WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")

# Detecção de avalanche: se muitos sites DISTINTOS abrirem incidente em pouco
# tempo, é sinal de falha no monitoramento (ex: link da matriz/Zabbix caiu),
# não N problemas reais e independentes — consolida tudo num chamado só.
FLOOD_THRESHOLD = 10       # nº de sites distintos pra considerar "avalanche"
FLOOD_WINDOW_MINUTES = 5   # janela de tempo em que isso é contado
MASS_KEY = "_mass"
RECENT_KEY = "_recent"

# Se o mesmo site voltar a disparar dentro dessa janela depois de ter
# normalizado totalmente, reaproveita o chamado já existente (como
# acompanhamento) em vez de abrir um chamado novo. Sem isso, um link que
# fica oscilando firing/resolved por horas (ex: perda de pacote intermitente)
# abre um chamado novo a cada ciclo — e o Pending period da regra no Grafana
# não resolve isso, porque ele só atrasa a entrada em "firing", não evita que
# o alerta normalize e dispare de novo pouco depois.
REOPEN_WINDOW_MINUTES = 60

# Ao normalizar TODOS os sintomas de um incidente, o chamado recebe uma SOLUCAO (o GLPI muda o status para
# "Solucionado") e, com True aqui, e fechado em seguida (status "Fechado"). Com False fica so "Solucionado"
# (o GLPI fecha sozinho depois do prazo da entidade). Se o problema voltar dentro de REOPEN_WINDOW_MINUTES,
# o chamado volta para "Em atendimento" e recebe o acompanhamento de reincidencia.
CLOSE_TICKET_ON_RESOLVE = True

# O GLPI exige um TECNICO (usuario) atribuido para solucionar/fechar um chamado (o grupo tecnico nao basta).
# Se ninguem assumiu o chamado, o webhook atribui este usuario antes de encerrar (padrao: a propria conta de servico).
GLPI_TECHNICIAN_ID = GLPI_REQUESTER_ID

# O GLPI tambem exige LOCALIZACAO para solucionar/fechar. Chamado sem localizacao (site fora do mapa) recebe esta
# antes de encerrar (2 = HQ / matriz).
GLPI_DEFAULT_LOCATION_ID = 2

# Correlacao de tuneis (topologia hub-and-spoke: todos os tuneis SD-WAN partem da matriz, host FW HQ). Quando
# VARIOS sites perdem tunel ao mesmo tempo, ou ja existe um incidente aberto no site da matriz (o link), a causa e o
# link da matriz: os tuneis viram ACOMPANHAMENTO do chamado do HQ em vez de abrir um chamado por site.
TUNNEL_ALERTNAMES = {"Perda de pacote - Tuneis SDWAN", "Status VPN - Link fora", "Tempo de resposta - VPNs alto"}
TUNNEL_HUB_SITE = "HQ"   # site do chamado do link da matriz
TUNNEL_MIN_SITES = 3           # sites distintos com tunel caido que caracterizam falha do hub
TUNNEL_WINDOW_MINUTES = 5      # janela em que isso e contado (alem do mesmo lote de alertas do Grafana)
TUNNEL_RECENT_KEY = "_tunnel_recent"

# Alertas que NAO sao de rede: nao entram na contagem de avalanche nem sao absorvidos pelo chamado de emergencia (como o
# ERP). Falhas de backup chegam com site=BACKUP e a infraestrutura Proxmox com site=INFRA (regras do Grafana).
NON_NETWORK_SITES = {"ERP", "BACKUP", "INFRA"}
# Categoria do GLPI por site (o que nao estiver aqui usa GLPI_CATEGORY_ID). IDs de exemplo: ajuste aos do seu GLPI.
CATEGORY_BY_SITE = {"BACKUP": 43, "INFRA": 39}
TITLE_SUFFIX = {TUNNEL_HUB_SITE: " (link da matriz e túneis)", "BACKUP": " (backup Proxmox)", "INFRA": " (infraestrutura Proxmox)"}
RECENTLY_CLOSED_KEY = "_recently_closed"

STATE_FILE = Path(os.environ.get("STATE_FILE", "/opt/grafana_glpi/active_alerts.json"))  # guarda, por site, o chamado aberto e os sintomas ativos
LOG_FILE = os.environ.get("LOG_FILE") or None   # None = log to stderr (journald)

# ---------------------------------------------------------------------------
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
app = Flask(__name__)


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def find_site_by_fingerprint(state: dict, fingerprint) -> str:
    """Devolve o site em cujo chamado esse sintoma (fingerprint) esta registrado, ou "". Sintomas de tunel que foram
    para o chamado do link da matriz ficam sob o site do hub, nao sob o site de origem; sem esta busca a
    normalizacao nao os encontraria e o chamado nunca fecharia."""
    if not fingerprint:
        return ""
    for key, info in state.items():
        if key.startswith("_") or not isinstance(info, dict):
            continue
        if fingerprint in info.get("active", {}):
            return key
    return ""


def register_site_open_and_check_flood(state: dict, site: str) -> set:
    """Registra a abertura de um novo site na janela recente e devolve o
    conjunto de sites distintos que abriram dentro da janela de tempo."""
    now = datetime.utcnow()
    cutoff = now - timedelta(minutes=FLOOD_WINDOW_MINUTES)
    recent = [
        r for r in state.get(RECENT_KEY, [])
        if datetime.fromisoformat(r["ts"]) > cutoff
    ]
    recent.append({"site": site, "ts": now.isoformat()})
    state[RECENT_KEY] = recent
    return {r["site"] for r in recent}


def try_reopen_recent_ticket(session_token: str, state: dict, site: str, details: str):
    """Se o site tiver um chamado fechado há menos de REOPEN_WINDOW_MINUTES,
    reabre ele como acompanhamento (e já registra o site como ativo de novo
    em 'state') e devolve o ticket_id. Caso contrário (nunca fechou, ou
    fechou há tempo demais), devolve None e deixa o chamador abrir um
    chamado novo normalmente."""
    recently_closed = state.get(RECENTLY_CLOSED_KEY, {})
    info = recently_closed.get(site)
    if not info:
        return None

    closed_at = datetime.fromisoformat(info["closed_at"])
    if datetime.utcnow() - closed_at >= timedelta(minutes=REOPEN_WINDOW_MINUTES):
        del recently_closed[site]
        return None

    ticket_id = info["ticket_id"]
    del recently_closed[site]
    try:
        glpi_reopen_ticket(session_token, ticket_id)
    except Exception:
        logging.exception(f"Nao consegui reabrir o chamado #{ticket_id} de '{site}'; vai abrir um chamado novo")
        return None
    glpi_add_followup(
        session_token,
        ticket_id,
        f"Problema reincidiu em {site} (reaberto dentro da janela de "
        f"{REOPEN_WINDOW_MINUTES} min após ter normalizado):\n\n{details}",
    )
    state[site] = {"ticket_id": ticket_id, "active": {}}
    return ticket_id


def glpi_init_session() -> str:
    r = requests.get(
        f"{GLPI_URL}/initSession",
        headers={
            "App-Token": GLPI_APP_TOKEN,
            "Authorization": f"user_token {GLPI_USER_TOKEN}",
        },
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["session_token"]


def glpi_kill_session(session_token: str) -> None:
    requests.get(
        f"{GLPI_URL}/killSession",
        headers={"App-Token": GLPI_APP_TOKEN, "Session-Token": session_token},
        timeout=10,
    )


def glpi_create_ticket(session_token: str, title: str, content: str, urgency: int, site: str) -> int:
    payload = {
        "input": {
            "name": title,
            "content": content,
            "urgency": urgency,
            "impact": urgency,
            "type": 1,  # 1 = incidente
            "entities_id": GLPI_ENTITY_ID,
        }
    }
    categoria = CATEGORY_BY_SITE.get(site.upper(), GLPI_CATEGORY_ID)
    if categoria:
        payload["input"]["itilcategories_id"] = categoria
    if GLPI_GROUP_ID:
        payload["input"]["_groups_id_assign"] = GLPI_GROUP_ID
    if GLPI_REQUESTER_ID:
        payload["input"]["_users_id_requester"] = GLPI_REQUESTER_ID
    location_id = SITE_TO_LOCATION_ID.get(site.upper())
    if location_id:
        payload["input"]["locations_id"] = location_id

    r = requests.post(
        f"{GLPI_URL}/Ticket",
        headers={
            "App-Token": GLPI_APP_TOKEN,
            "Session-Token": session_token,
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["id"]


def glpi_add_followup(session_token: str, ticket_id: int, content: str) -> None:
    r = requests.post(
        f"{GLPI_URL}/Ticket/{ticket_id}/ITILFollowup",
        headers={
            "App-Token": GLPI_APP_TOKEN,
            "Session-Token": session_token,
            "Content-Type": "application/json",
        },
        json={"input": {"itemtype": "Ticket", "items_id": ticket_id, "content": content}},
        timeout=10,
    )
    r.raise_for_status()


def _glpi_check(r) -> None:
    """Como raise_for_status(), mas a mensagem inclui a resposta do GLPI (o motivo do erro) e um PUT/POST
    com HTTP 200 que o GLPI marca como false no corpo tambem conta como erro."""
    falhou = r.status_code >= 400 or r.status_code == 207
    if not falhou:
        try:
            dados = r.json()
        except ValueError:
            dados = None
        if isinstance(dados, list):
            falhou = any(isinstance(i, dict) and any(v is False for v in i.values()) for i in dados)
    if falhou:
        raise RuntimeError(f"GLPI respondeu {r.status_code} em {r.request.method} {r.url}: {r.text[:600]}")


def _glpi_headers(session_token: str) -> dict:
    return {
        "App-Token": GLPI_APP_TOKEN,
        "Session-Token": session_token,
        "Content-Type": "application/json",
    }


def glpi_ensure_technician(session_token: str, ticket_id: int) -> None:
    """O GLPI exige TECNICO (usuario, nao so grupo) atribuido antes de solucionar/fechar. Se ninguem assumiu o
    chamado, atribui a conta de servico; se um tecnico ja esta atribuido, nao mexe."""
    r = requests.get(f"{GLPI_URL}/Ticket/{ticket_id}/Ticket_User", headers=_glpi_headers(session_token), timeout=10)
    _glpi_check(r)
    if any(isinstance(u, dict) and int(u.get("type", 0)) == 2 for u in (r.json() or [])):
        return
    r = requests.post(
        f"{GLPI_URL}/Ticket_User",
        headers=_glpi_headers(session_token),
        json={"input": {"tickets_id": ticket_id, "users_id": GLPI_TECHNICIAN_ID, "type": 2}},
        timeout=10,
    )
    _glpi_check(r)
    logging.info(f"Chamado #{ticket_id}: sem tecnico atribuido, atribuido o usuario {GLPI_TECHNICIAN_ID} (exigencia do GLPI para encerrar)")


def glpi_ensure_location(session_token: str, ticket_id: int, site: str = "") -> None:
    """O GLPI exige LOCALIZACAO para solucionar/fechar. Chamado sem localizacao (site fora do mapa, chamado antigo)
    recebe a do site (SITE_TO_LOCATION_ID) ou, na falta, GLPI_DEFAULT_LOCATION_ID."""
    r = requests.get(f"{GLPI_URL}/Ticket/{ticket_id}", headers=_glpi_headers(session_token), timeout=10)
    _glpi_check(r)
    if int(r.json().get("locations_id") or 0) > 0:
        return
    location_id = SITE_TO_LOCATION_ID.get((site or "").upper()) or GLPI_DEFAULT_LOCATION_ID
    r = requests.put(
        f"{GLPI_URL}/Ticket/{ticket_id}",
        headers=_glpi_headers(session_token),
        json={"input": {"locations_id": location_id}},
        timeout=10,
    )
    _glpi_check(r)
    logging.info(f"Chamado #{ticket_id}: sem localizacao, definida a localizacao {location_id} (exigencia do GLPI para encerrar)")


def glpi_resolve_and_close_ticket(session_token: str, ticket_id: int, solution_text: str, site: str = "") -> None:
    """Garante o tecnico e a localizacao, registra a SOLUCAO (status "Solucionado") e, se CLOSE_TICKET_ON_RESOLVE, fecha (status 6).
    Se o GLPI recusar a solucao, tenta mudar o status direto. No fim confere o status lido de volta."""
    headers = _glpi_headers(session_token)
    glpi_ensure_technician(session_token, ticket_id)
    glpi_ensure_location(session_token, ticket_id, site)
    try:
        r = requests.post(
            f"{GLPI_URL}/ITILSolution",
            headers=headers,
            json={"input": {"itemtype": "Ticket", "items_id": ticket_id, "content": solution_text}},
            timeout=10,
        )
        _glpi_check(r)
    except Exception as e:
        logging.warning(f"GLPI recusou registrar a solucao no chamado #{ticket_id} ({e}); tentando mudar o status direto")
        r = requests.put(
            f"{GLPI_URL}/Ticket/{ticket_id}",
            headers=headers,
            json={"input": {"status": 5}},
            timeout=10,
        )
        _glpi_check(r)
    if CLOSE_TICKET_ON_RESOLVE:
        r = requests.put(
            f"{GLPI_URL}/Ticket/{ticket_id}",
            headers=headers,
            json={"input": {"status": 6}},
            timeout=10,
        )
        _glpi_check(r)
    esperado = 6 if CLOSE_TICKET_ON_RESOLVE else 5
    r = requests.get(f"{GLPI_URL}/Ticket/{ticket_id}", headers=headers, timeout=10)
    _glpi_check(r)
    atual = int(r.json().get("status", 0))
    if atual != esperado:
        raise RuntimeError(f"GLPI nao aplicou o status esperado no chamado #{ticket_id}: esperado {esperado}, atual {atual}")


def glpi_reopen_ticket(session_token: str, ticket_id: int) -> None:
    """Volta o chamado para "Em atendimento (atribuido)" (status 2) quando o problema reincide."""
    r = requests.put(
        f"{GLPI_URL}/Ticket/{ticket_id}",
        headers={
            "App-Token": GLPI_APP_TOKEN,
            "Session-Token": session_token,
            "Content-Type": "application/json",
        },
        json={"input": {"status": 2}},
        timeout=10,
    )
    _glpi_check(r)
    r = requests.get(f"{GLPI_URL}/Ticket/{ticket_id}", headers=_glpi_headers(session_token), timeout=10)
    _glpi_check(r)
    atual = int(r.json().get("status", 0))
    if atual in (5, 6):
        raise RuntimeError(f"GLPI nao reabriu o chamado #{ticket_id}: continua com status {atual}")


def close_ticket_safely(session_token: str, ticket_id: int, solution_text: str, site: str = "") -> None:
    """Falha ao encerrar nunca derruba o processamento do alerta: o acompanhamento ja foi registrado e o
    site "zera" normalmente; so fica o aviso no log para fechar o chamado na mao."""
    try:
        glpi_resolve_and_close_ticket(session_token, ticket_id, solution_text, site)
        logging.info(f"Chamado #{ticket_id} solucionado" + (" e fechado" if CLOSE_TICKET_ON_RESOLVE else "") + " automaticamente")
    except Exception:
        logging.exception(f"Falha ao encerrar automaticamente o chamado #{ticket_id} (feche manualmente)")


def severity_to_urgency(labels: dict) -> int:
    severity = (labels.get("severity") or "").lower()
    return {"critical": 5, "warning": 3}.get(severity, 3)


GLPI_BASE_URL = GLPI_URL.rsplit("/apirest.php", 1)[0]  # ex: http://glpi.example.com


def send_email_alert(subject: str, text_body: str, html_body: str = None) -> None:
    return None


def render_incident_email_html(**kw) -> str:
    return ""


def render_mass_incident_email_html(**kw) -> str:
    return ""


NON_SITE_BRACKET_TOKENS = {"Default_AWS", "Default_DNS"}
ERP_SITE = "ERP"
SWITCHES_SITE = "HQ_SWITCHES"
ZABBIX_HOST_TO_SITE = {"FW BR01": "BRANCH01", "FW BR02": "BRANCH02"}


def extract_site(labels: dict) -> str:
    if labels.get("site"):
        return labels["site"]
    if labels.get("alertname", "").startswith("ERP"):
        return ERP_SITE
    if labels.get("alertname", "").startswith("Switches"):
        return SWITCHES_SITE
    item = labels.get("item", "")
    m = re.search(r"\[([A-Za-z0-9_]+)\]", item)
    if m and m.group(1) not in NON_SITE_BRACKET_TOKENS:
        return m.group(1)
    host = labels.get("host")
    if host:
        return ZABBIX_HOST_TO_SITE.get(host, host)
    return labels.get("instance") or "geral"


@app.route("/grafana-webhook", methods=["POST"])
def grafana_webhook():
    if request.headers.get("X-Webhook-Secret") != WEBHOOK_SECRET:
        logging.warning("Requisição rejeitada: segredo inválido")
        return jsonify({"error": "unauthorized"}), 401

    body = request.get_json(force=True, silent=True) or {}
    alerts = body.get("alerts", [])
    # state: { site: {"ticket_id": int, "active": {fingerprint: alertname}} }
    # agrupa por SITE: enquanto um site tiver qualquer sintoma ativo, tudo cai
    # no mesmo chamado; quando o último sintoma normaliza, o site "zera" e o
    # próximo problema ali abre um chamado novo.
    state = load_state()

    session_token = None
    try:
        session_token = glpi_init_session()

        # Correlacao de tuneis: conta os sites distintos com tunel caido neste lote + na janela recente, ANTES de abrir
        # qualquer chamado (o Grafana manda todos os tuneis de uma queda da matriz na mesma notificacao).
        tunnel_flood = False
        try:
            _agora = datetime.utcnow()
            _corte = _agora - timedelta(minutes=TUNNEL_WINDOW_MINUTES)
            _recentes = [r for r in state.get(TUNNEL_RECENT_KEY, []) if datetime.fromisoformat(r["ts"]) > _corte]
            _vistos = {r["site"] for r in _recentes}
            for _a in alerts:
                _l = _a.get("labels", {})
                if _a.get("status") == "firing" and _l.get("alertname") in TUNNEL_ALERTNAMES:
                    _s = extract_site(_l)
                    if _s not in _vistos:
                        _vistos.add(_s)
                        _recentes.append({"site": _s, "ts": _agora.isoformat()})
            state[TUNNEL_RECENT_KEY] = _recentes
            tunnel_flood = len(_vistos - {TUNNEL_HUB_SITE}) >= TUNNEL_MIN_SITES
        except Exception:
            logging.exception("Falha na correlacao de tuneis (segue sem correlacao)")

        for alert in alerts:
            fingerprint = alert.get("fingerprint")
            status = alert.get("status")  # "firing" ou "resolved"
            labels = alert.get("labels", {})
            annotations = alert.get("annotations", {})
            alertname = labels.get("alertname", "Alerta Grafana")
            site = extract_site(labels)
            origin_site = site
            registered_in = find_site_by_fingerprint(state, fingerprint)
            if registered_in:
                site = registered_in      # sintoma ja registrado: normalizacao/repeticao seguem o chamado onde ele esta
            elif (status == "firing" and alertname in TUNNEL_ALERTNAMES and site != TUNNEL_HUB_SITE
                  and state.get(site) is None and (state.get(TUNNEL_HUB_SITE) is not None or tunnel_flood)):
                site = TUNNEL_HUB_SITE    # tunel de um site sem chamado proprio: acompanhamento do chamado do link da matriz
            if site != origin_site:
                alertname = f"{alertname} [{origin_site}]"
            is_non_network = site in NON_NETWORK_SITES   # (nome historico) alerta que nao e de rede: fora da avalanche
            logging.info(f"DEBUG labels recebidos: {json.dumps(labels, ensure_ascii=False)} -> site extraido='{site}'")
            summary = annotations.get("summary") or annotations.get("description") or ""
            url = alert.get("generatorURL", "")

            try:
                if status == "firing":
                    site_state = state.get(site)
                    mass_state = state.get(MASS_KEY)

                    if site_state and fingerprint in site_state["active"]:
                        continue  # esse sintoma específico já está registrado, não duplica
                    if mass_state and fingerprint in mass_state["active"]:
                        continue  # já registrado dentro do incidente de avalanche

                    instance_label = labels.get("instance")
                    details = (
                        f"Alerta: {alertname}\n"
                        f"Site/host: {site}\n"
                        + (f"Item: {labels.get('item')}\n" if labels.get("item") else "")
                        + (f"Instância: {instance_label}\n" if instance_label else "")
                        + f"Descrição: {summary or 'N/A'}\n"
                        f"Link do painel: {url or 'N/A'}\n"
                        f"Início: {alert.get('startsAt', 'N/A')}"
                    )
                    urgency = severity_to_urgency(labels)

                    if mass_state is not None and not is_non_network:
                        # já estamos em modo emergência: qualquer site novo vira
                        # acompanhamento no chamado único, não abre chamado próprio
                        # (ERP nunca entra aqui — não é uma "filial", não deve ser
                        # absorvido por um chamado de avalanche de rede)
                        ticket_id = mass_state["ticket_id"]
                        glpi_add_followup(
                            session_token,
                            ticket_id,
                            f"Mais um site afetado durante o evento:\n\n{details}",
                        )
                        mass_state["active"][fingerprint] = {"site": site, "alertname": alertname}
                        save_state(state)
                        logging.warning(f"Chamado de emergência #{ticket_id} recebeu novo site: {site} ({alertname})")

                    elif site_state is None:
                        # primeiro sintoma desse site nesta rodada: tenta reaproveitar
                        # um chamado recém-fechado (site oscilando) antes de contar
                        # pra avalanche ou abrir um chamado novo
                        reopened_ticket_id = try_reopen_recent_ticket(session_token, state, site, details)

                        if reopened_ticket_id is not None:
                            state[site]["active"][fingerprint] = alertname
                            save_state(state)
                            logging.info(
                                f"Chamado #{reopened_ticket_id} REABERTO em '{site}' "
                                f"(reincidência; sintoma: {alertname})"
                            )
                        else:
                            # (ERP nunca participa da contagem de avalanche de rede)
                            distinct_sites = set() if is_non_network else register_site_open_and_check_flood(state, site)

                            if (not is_non_network) and len(distinct_sites) >= FLOOD_THRESHOLD:
                                title = "[Grafana] ALERTA - Possível falha geral de monitoramento"
                                content = (
                                    f"{len(distinct_sites)} sites distintos começaram a disparar alertas em "
                                    f"menos de {FLOOD_WINDOW_MINUTES} minutos — pode ser uma queda real em massa "
                                    f"OU falha no próprio monitoramento (ex: link da matriz/Zabbix fora do ar).\n\n"
                                    f"VERIFIQUE a conectividade da matriz e o Zabbix ANTES de tratar site a site. "
                                    f"Confira também se não há outros chamados individuais já abertos antes desse evento.\n\n"
                                    f"Sites envolvidos até agora: {', '.join(sorted(distinct_sites))}\n\n"
                                    f"Primeiro sintoma registrado:\n{details}"
                                )
                                ticket_id = glpi_create_ticket(session_token, title, content, 5, site)
                                state[MASS_KEY] = {
                                    "ticket_id": ticket_id,
                                    "active": {fingerprint: {"site": site, "alertname": alertname}},
                                }
                                save_state(state)
                                logging.warning(
                                    f"MODO EMERGÊNCIA: chamado #{ticket_id} aberto "
                                    f"({len(distinct_sites)} sites em {FLOOD_WINDOW_MINUTES}min)"
                                )
                                send_email_alert(
                                    f"[URGENTE] Possível falha geral de monitoramento — chamado #{ticket_id}",
                                    content,
                                    render_mass_incident_email_html(
                                        ticket_id=ticket_id,
                                        flood_window_minutes=FLOOD_WINDOW_MINUTES,
                                        distinct_sites=distinct_sites,
                                        first_alertname=alertname,
                                        first_site=site,
                                    ),
                                )
                            else:
                                title = f"[Grafana] Incidente — {site}" + TITLE_SUFFIX.get(site, "")
                                content = f"Alerta disparado automaticamente pelo Grafana.\n\n{details}"
                                ticket_id = glpi_create_ticket(session_token, title, content, urgency, site)
                                state[site] = {"ticket_id": ticket_id, "active": {fingerprint: alertname}}
                                save_state(state)
                                logging.info(f"Chamado #{ticket_id} aberto para incidente em '{site}' (1º sintoma: {alertname})")
                                send_email_alert(
                                    f"[Grafana] Novo incidente — {site} (chamado #{ticket_id})",
                                    content,
                                    render_incident_email_html(
                                        alertname=alertname,
                                        site=site,
                                        description=summary,
                                        instance_label=instance_label,
                                        starts_at=alert.get("startsAt", "N/A"),
                                        ticket_id=ticket_id,
                                        severity=labels.get("severity"),
                                        panel_url=url,
                                    ),
                                )

                    else:
                        # site já tem chamado próprio aberto: acrescenta sintoma como acompanhamento
                        ticket_id = site_state["ticket_id"]
                        glpi_add_followup(
                            session_token,
                            ticket_id,
                            f"Novo sintoma associado a este incidente:\n\n{details}",
                        )
                        site_state["active"][fingerprint] = alertname
                        save_state(state)
                        logging.info(f"Chamado #{ticket_id} recebeu novo sintoma em '{site}': {alertname}")

                elif status == "resolved":
                    site_state = state.get(site)
                    mass_state = state.get(MASS_KEY)

                    if site_state and fingerprint in site_state["active"]:
                        ticket_id = site_state["ticket_id"]
                        del site_state["active"][fingerprint]

                        if site_state["active"]:
                            glpi_add_followup(
                                session_token,
                                ticket_id,
                                f"Sintoma normalizado: {alertname} (ainda há outros sintomas ativos nesse incidente).",
                            )
                            logging.info(f"Chamado #{ticket_id}: sintoma '{alertname}' normalizado, incidente em '{site}' continua ativo")
                        else:
                            glpi_add_followup(
                                session_token,
                                ticket_id,
                                f"Todos os sintomas normalizados em {site} (último: {alertname}). Incidente encerrado.",
                            )
                            close_ticket_safely(
                                session_token,
                                ticket_id,
                                f"Incidente normalizado automaticamente: todos os sintomas voltaram ao normal em {site} "
                                f"(último: {alertname}). Chamado encerrado pelo Grafana.",
                                site,
                            )
                            state.setdefault(RECENTLY_CLOSED_KEY, {})[site] = {
                                "ticket_id": ticket_id,
                                "closed_at": datetime.utcnow().isoformat(),
                            }
                            del state[site]
                            logging.info(f"Chamado #{ticket_id}: incidente em '{site}' totalmente normalizado (reabre se reincidir em até {REOPEN_WINDOW_MINUTES}min)")

                        save_state(state)

                    elif mass_state and fingerprint in mass_state["active"]:
                        ticket_id = mass_state["ticket_id"]
                        del mass_state["active"][fingerprint]

                        if mass_state["active"]:
                            glpi_add_followup(
                                session_token,
                                ticket_id,
                                f"Normalizado: {alertname} em {site} (ainda há outros sites ativos nesse evento).",
                            )
                            logging.warning(f"Chamado de emergência #{ticket_id}: {site} normalizado, evento continua ativo")
                        else:
                            glpi_add_followup(
                                session_token,
                                ticket_id,
                                f"Todos os sites normalizados. Evento de falha geral encerrado (último: {alertname} em {site}).",
                            )
                            close_ticket_safely(
                                session_token,
                                ticket_id,
                                f"Evento de falha geral normalizado automaticamente: todos os sites voltaram ao normal "
                                f"(último: {alertname} em {site}). Chamado encerrado pelo Grafana.",
                                site,
                            )
                            del state[MASS_KEY]
                            logging.warning(f"Chamado de emergência #{ticket_id}: evento totalmente normalizado")

                        save_state(state)
            except Exception:
                logging.exception(f"Falha processando alerta '{alertname}' (site={site}, fingerprint={fingerprint})")
    finally:
        if session_token:
            glpi_kill_session(session_token)

    return jsonify({"ok": True}), 200


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "up"}), 200


if __name__ == "__main__":
    # Em produção isso roda atrás do systemd + Apache reverse proxy (ver abaixo),
    # não direto com app.run(). Isso aqui é só pra teste manual.
    app.run(host="127.0.0.1", port=8787)
