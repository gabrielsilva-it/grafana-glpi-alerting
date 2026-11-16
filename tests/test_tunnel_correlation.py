"""Correlacao de tuneis hub-and-spoke: quedas de tunel viram acompanhamento do chamado do link da matriz.

Uso: python test_tunnel_correlation.py <grafana_glpi_webhook.py> [chaves-reais]
Precisa de: pip install flask requests
"""
import importlib.util
import json
import logging
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timedelta

BASE = sys.argv[1]
CHAVES_REAIS = len(sys.argv) > 2 and sys.argv[2] == "chaves-reais"
AQUI = os.path.dirname(os.path.abspath(__file__))

# configuracao usada pelos testes (a mesma estrutura de um GLPI real, com valores de exemplo)
os.environ.update({
    "GLPI_URL": "http://glpi.test/apirest.php",
    "GLPI_APP_TOKEN": "app",
    "GLPI_USER_TOKEN": "user",
    "GLPI_CATEGORY_ID": "49",
    "GLPI_GROUP_ID": "2",
    "GLPI_REQUESTER_ID": "2",
    "WEBHOOK_SECRET": "segredo",
    "SITES_FILE": os.path.join(AQUI, "sites.test.json"),
})

tmp = tempfile.mkdtemp()
patched = os.path.join(tmp, "webhook_under_test.py")
original = open(BASE, encoding="utf-8", newline="").read()
if CHAVES_REAIS:
    original = original.replace('"_recently_closed"', '"__recently_closed__"').replace('"_mass"', '"__mass__"').replace('"_recent"', '"__recent__"')
open(patched, "w", encoding="utf-8", newline="").write(original)
compile(original, patched, "exec")

def load():
    spec = importlib.util.spec_from_file_location("wh", patched)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.STATE_FILE = type(mod.STATE_FILE)(os.path.join(tmp, "state.json"))
    if mod.STATE_FILE.exists():
        mod.STATE_FILE.unlink()
    mod.ZABBIX_HOST_TO_SITE["FW HQ"] = "HQ"       # em producao o host FW HQ ja vira o site HQ (log: "aberto para incidente em 'HQ'")
    return mod


class Resp:
    def __init__(self, status=200, body=None, method="GET", url=""):
        self.status_code, self._body = status, body if body is not None else {}
        self.request = type("Req", (), {"method": method})()
        self.url = url
        self.text = json.dumps(self._body)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP %d" % self.status_code)

    def json(self):
        return self._body


class FakeGLPI:
    """GLPI de mentira (mesmas regras do teste do encerramento: exige tecnico e localizacao para solucionar/fechar)."""

    def __init__(self):
        self.calls, self.next_id, self.tickets = [], 100, {}

    def _go(self, method, url, **kw):
        import re
        path = url.split("/apirest.php")[1]
        self.calls.append((method, path, kw.get("json")))
        entrada = (kw.get("json") or {}).get("input", {})
        mt = re.match(r"^/Ticket/(\d+)(/Ticket_User)?$", path)
        tk = self.tickets.get(int(mt.group(1))) if mt else None
        if path.startswith("/initSession"):
            return Resp(200, {"session_token": "tok"}, method, url)
        if method == "POST" and path == "/Ticket":
            self.next_id += 1
            self.tickets[self.next_id] = {"status": 2, "tecnico": False, "loc": entrada.get("locations_id") or 0, "name": entrada.get("name")}
            return Resp(201, {"id": self.next_id}, method, url)
        if method == "GET" and mt and mt.group(2) and tk is not None:
            return Resp(200, [{"type": 1, "users_id": 2}] + ([{"type": 2, "users_id": 9}] if tk["tecnico"] else []), method, url)
        if method == "GET" and mt and tk is not None:
            return Resp(200, {"id": int(mt.group(1)), "status": tk["status"], "locations_id": tk["loc"]}, method, url)
        if method == "POST" and path == "/Ticket_User":
            if entrada.get("type") == 2:
                self.tickets[entrada["tickets_id"]]["tecnico"] = True
            return Resp(201, {"id": 1}, method, url)
        if method == "POST" and path == "/ITILSolution":
            t = self.tickets[entrada["items_id"]]
            if not t["tecnico"] or not t["loc"]:
                return Resp(400, ["ERROR_GLPI_ADD", "exigencia"], method, url)
            t["status"] = 5
            return Resp(201, {"id": 1}, method, url)
        if method == "PUT" and mt and tk is not None and "locations_id" in entrada:
            tk["loc"] = entrada["locations_id"]
            return Resp(200, [{mt.group(1): True, "message": ""}], method, url)
        if method == "PUT" and mt and tk is not None and "status" in entrada:
            if not (entrada["status"] in (5, 6) and (not tk["tecnico"] or not tk["loc"])):
                tk["status"] = entrada["status"]
            return Resp(200, [{mt.group(1): True, "message": ""}], method, url)
        return Resp(200, {}, method, url)

    def get(self, url, **kw):
        return self._go("GET", url, **kw)

    def post(self, url, **kw):
        return self._go("POST", url, **kw)

    def put(self, url, **kw):
        return self._go("PUT", url, **kw)

    def ops(self):
        return [(m, p) for m, p, _ in self.calls if not p.startswith(("/initSession", "/killSession"))]

    def novos(self):
        return [b["input"] for m, p, b in self.calls if m == "POST" and p == "/Ticket"]

    def followups(self, ticket):
        return [b["input"]["content"] for m, p, b in self.calls if m == "POST" and p == "/Ticket/%d/ITILFollowup" % ticket]

    def fechou(self, ticket):
        return ("PUT", "/Ticket/%d" % ticket) in self.ops() and ("POST", "/ITILSolution") in self.ops()


SITES = ["BRANCH02", "BRANCH11", "BRANCH12", "BRANCH05", "BRANCH03", "BRANCH04", "BRANCH01", "BRANCH06", "BRANCH07"]
VPN = {s: "BR%02d" % (i + 1) for i, s in enumerate(SITES)}


def tunel(site, n=2, nome="Perda de pacote - Tuneis SDWAN", status="firing"):
    return {"status": status, "fingerprint": "fp-%s-%d-%s" % (site, n, nome[:6]),
            "labels": {"alertname": nome, "grafana_folder": "GLPI Alerts", "host": "FW HQ", "severity": "critical",
                       "item": "SD-WAN [%s]:[HQx%s_VPN%d]: Packets loss" % (site, VPN[site], n)},
            "annotations": {"summary": "perda de pacote no tunel"}, "startsAt": "2026-10-19T11:03:00Z", "generatorURL": ""}


def link(status="firing"):
    return {"status": status, "fingerprint": "fp-link-hq-wan2",
            "labels": {"alertname": "Perda de Pacotes - LINKs", "grafana_folder": "GLPI Alerts", "host": "FW HQ", "severity": "critical",
                       "item": "SD-WAN [Default_AWS]:[wan2]: Packets loss"},
            "annotations": {"summary": "perda de pacote no link wan2 da matriz"}, "startsAt": "2026-10-19T11:39:00Z", "generatorURL": ""}


def outro(site, status="firing", nome="Perda de Pacotes - LINKs"):
    return {"status": status, "fingerprint": "fp-outro-" + site,
            "labels": {"alertname": nome, "site": site, "severity": "critical"},
            "annotations": {"summary": "x"}, "startsAt": "2026-10-19T11:00:00Z", "generatorURL": ""}


def enviar(mod, alertas):
    c = mod.app.test_client()
    r = c.post("/grafana-webhook", data=json.dumps({"alerts": alertas}),
               headers={"X-Webhook-Secret": "segredo", "Content-Type": "application/json"})
    assert r.status_code == 200, r.status_code


def estado(mod):
    return json.loads(mod.STATE_FILE.read_text(encoding="utf-8")) if mod.STATE_FILE.exists() else {}


def sites_com_chamado(mod):
    return sorted(k for k in estado(mod) if not k.startswith("_"))


# ---- 1) o que aconteceu em 19/10: 18 alertas de tunel (9 sites x 2 tuneis) no MESMO lote -> UM chamado (HQ)
mod = load()
g = FakeGLPI()
mod.requests = g
lote = [t for s in SITES for t in (tunel(s, 2), tunel(s, 3))]
enviar(mod, lote)
novos = g.novos()
print("LOTE DE 18 TUNEIS: chamados novos =", len(novos), "| titulo:", novos[0]["name"])
assert len(novos) == 1, novos                                                                # antes: 9 chamados
assert novos[0]["name"] == "[Grafana] Incidente — HQ (link da matriz e túneis)", novos[0]["name"]
assert novos[0]["locations_id"] == 2, novos[0]                                               # localizacao HQ
assert sites_com_chamado(mod) == sorted(["HQ"]), sites_com_chamado(mod)
assert len(estado(mod)["HQ"]["active"]) == 18
fu = g.followups(101)
assert len(fu) == 17, len(fu)                                                                # 1o sintoma abre; os outros 17 sao acompanhamento
assert any("Item: SD-WAN [BRANCH02]:[HQxBR01_VPN3]: Packets loss" in c and "[BRANCH02]" in c for c in fu), fu[0]      # acompanhamento diz qual tunel
assert any("[BRANCH07]" in c for c in fu) and any("HQxBR09_VPN3" in c for c in fu)
assert "Item: SD-WAN [BRANCH02]:[HQxBR01_VPN2]: Packets loss" in novos[0]["content"]      # 1o sintoma tambem mostra o tunel

# 36 min depois chega o alerta do link da matriz: entra no MESMO chamado, nao abre outro
g.calls.clear()
enviar(mod, [link()])
assert g.novos() == [] and len(g.followups(101)) == 1, g.ops()
assert "Novo sintoma associado" in g.followups(101)[0] and "Perda de Pacotes - LINKs" in g.followups(101)[0]
assert len(estado(mod)["HQ"]["active"]) == 19 and sites_com_chamado(mod) == ["HQ"]
print("LINK DA HQ_SWITCHES DEPOIS: acompanhamento no chamado #101 (sem chamado novo)")

# repeticao do mesmo lote (o Grafana re-notifica): nada novo
g.calls.clear()
enviar(mod, lote + [link()])
assert g.ops() == [], g.ops()

# normalizacao: os tuneis normalizam pelo fingerprint (o site de origem nao tem estado); o chamado so fecha com o ULTIMO sintoma
g.calls.clear()
enviar(mod, [tunel(s, n, status="resolved") for s in SITES for n in (2, 3)])
assert not g.fechou(101) and "HQ" in estado(mod) and list(estado(mod)["HQ"]["active"]) == ["fp-link-hq-wan2"], estado(mod)
assert len(g.followups(101)) == 18
assert any("normalizado" in c and "[BRANCH02]" in c for c in g.followups(101)), g.followups(101)[:2]
g.calls.clear()
enviar(mod, [link("resolved")])
assert g.fechou(101) and g.tickets[101]["status"] == 6, (g.ops(), g.tickets)
assert "HQ" not in estado(mod) and estado(mod)[mod.RECENTLY_CLOSED_KEY]["HQ"]["ticket_id"] == 101
print("NORMALIZACAO: so fecha com o ultimo sintoma (o link); chamado #101 Fechado")

# nova queda de varios tuneis dentro de 60 min: REABRE o mesmo chamado (nao abre outro)
g.calls.clear()
enviar(mod, [tunel(s, 2) for s in SITES[:4]])
assert g.novos() == [] and ("PUT", "/Ticket/101") in g.ops(), g.ops()
assert g.tickets[101]["status"] == 2 and estado(mod)["HQ"]["ticket_id"] == 101
print("REINCIDENCIA: chamado #101 reaberto")

# ---- 2) o link alertou PRIMEIRO: o chamado do link existe; qualquer tunel (mesmo de 1 site) vira acompanhamento dele
mod = load()
g = FakeGLPI()
mod.requests = g
enviar(mod, [link()])
assert [n["name"] for n in g.novos()] == ["[Grafana] Incidente — HQ (link da matriz e túneis)"]
g.calls.clear()
enviar(mod, [tunel("BRANCH04", 2)])
assert g.novos() == [] and len(g.followups(101)) == 1 and "[BRANCH04]" in g.followups(101)[0], g.ops()
assert sites_com_chamado(mod) == sorted(["HQ"])
# alerta que NAO e de tunel, de outro site, continua abrindo o chamado proprio dele
g.calls.clear()
enviar(mod, [outro("BRANCH04")])
assert len(g.novos()) == 1 and "BRANCH04" in g.novos()[0]["name"] and "link da matriz" not in g.novos()[0]["name"], g.novos()
assert sites_com_chamado(mod) == sorted(["HQ", "BRANCH04"])
# agora o BRANCH04 tem chamado proprio: um tunel novo dele segue o chamado do BRANCH04 (comportamento de antes)
g.calls.clear()
enviar(mod, [tunel("BRANCH04", 3)])
assert g.novos() == [] and len(g.followups(102)) == 1 and g.followups(101) == [], (g.ops(), g.followups(101))
print("LINK PRIMEIRO: tuneis viram acompanhamento do chamado do link; outros alertas do site continuam proprios")

# ---- 3) abaixo do limite e sem incidente na matriz: 1 ou 2 sites continuam abrindo chamado por site
mod = load()
g = FakeGLPI()
mod.requests = g
enviar(mod, [tunel("BRANCH02", 2), tunel("BRANCH02", 3), tunel("BRANCH04", 2)])
assert [n["name"] for n in g.novos()] == ["[Grafana] Incidente — BRANCH02", "[Grafana] Incidente — BRANCH04"], g.novos()
assert sites_com_chamado(mod) == sorted(["BRANCH02", "BRANCH04"])
print("2 SITES: chamado por site, como antes")

# o 3o site, em OUTRA notificacao dentro de 5 min, ja caracteriza falha do hub: vai para o chamado do HQ
g.calls.clear()
enviar(mod, [tunel("BRANCH11", 2)])
assert [n["name"] for n in g.novos()] == ["[Grafana] Incidente — HQ (link da matriz e túneis)"], g.novos()
assert sites_com_chamado(mod) == sorted(["BRANCH02", "HQ", "BRANCH04"])
g.calls.clear()
enviar(mod, [tunel("BRANCH12", 2), tunel("BRANCH02", 3, nome="Tempo de resposta - VPNs alto")])
assert g.novos() == [] and len(g.followups(103)) == 1 and len(g.followups(101)) == 1, g.ops()       # BRANCH12 -> hub (#103); BRANCH02 tem chamado proprio (#101)
print("3o SITE EM OUTRA NOTIFICACAO: vai para o chamado do link da matriz")

# ---- 4) fora da janela de 5 min: os sites antigos nao contam (nao e uma queda simultanea)
mod = load()
g = FakeGLPI()
mod.requests = g
enviar(mod, [tunel("BRANCH02", 2)])
enviar(mod, [tunel("BRANCH04", 2)])
st = estado(mod)
for r in st[mod.TUNNEL_RECENT_KEY]:
    r["ts"] = (datetime.utcnow() - timedelta(minutes=6)).isoformat()
mod.STATE_FILE.write_text(json.dumps(st), encoding="utf-8")
g.calls.clear()
enviar(mod, [tunel("BRANCH11", 2)])
assert [n["name"] for n in g.novos()] == ["[Grafana] Incidente — BRANCH11"], g.novos()
print("FORA DA JANELA: chamado proprio")

# ---- 5) o que nao mudou: avalanche (10 sites, alertas que nao sao de tunel) continua consolidando no chamado de emergencia
mod = load()
g = FakeGLPI()
mod.requests = g
for i in range(12):
    enviar(mod, [outro("SITE%d" % i)])
assert mod.MASS_KEY in estado(mod) and len(g.novos()) == 10, (len(g.novos()), sorted(estado(mod)))
assert g.novos()[-1]["name"] == "[Grafana] ALERTA - Possível falha geral de monitoramento"
print("AVALANCHE (nao-tunel): inalterada")

# alerta de tunel cujo site ja e o do hub (host FW HQ -> HQ) nao e redirecionado nem renomeado
mod = load()
g = FakeGLPI()
mod.requests = g
a = tunel("BRANCH04", 2, nome="Status VPN - Link fora")
a["labels"].pop("item")
enviar(mod, [a])                                  # sem item: o site sai do host FW HQ = HQ (o proprio hub)
assert sites_com_chamado(mod) == sorted(["HQ"]) and "[" not in list(estado(mod)["HQ"]["active"].values())[0], estado(mod)

# segredo errado continua 401
mod = load()
mod.requests = FakeGLPI()
assert mod.app.test_client().post("/grafana-webhook", data="{}", headers={"X-Webhook-Secret": "errado"}).status_code == 401

print("TODOS OS TESTES PASSARAM")
