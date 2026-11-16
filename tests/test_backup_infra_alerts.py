"""Alertas de backup/infraestrutura (site BACKUP/INFRA): categoria propria e fora da logica de avalanche.

Uso: python test_backup_infra_alerts.py <grafana_glpi_webhook.py> [chaves-reais]
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
    mod.ZABBIX_HOST_TO_SITE["FW HQ"] = "HQ"
    mod.send_email_alert = lambda *a, **k: None
    return mod


class Resp:
    def __init__(self, status=200, body=None, method="GET", url=""):
        self.status_code, self._b, self.url = status, body if body is not None else {}, url
        self.request = type("Req", (), {"method": method})()
        self.text = json.dumps(self._b)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP %d" % self.status_code)

    def json(self):
        return self._b


class FakeGLPI:
    def __init__(self):
        self.calls, self.n, self.t = [], 100, {}

    def _go(self, m, url, **kw):
        path = url.split("/apirest.php")[1]
        inp = (kw.get("json") or {}).get("input", {})
        self.calls.append((m, path, inp))
        mt = re.match(r"^/Ticket/(\d+)(/Ticket_User)?$", path)
        tk = self.t.get(int(mt.group(1))) if mt else None
        if path.startswith("/initSession"):
            return Resp(200, {"session_token": "x"}, m, url)
        if m == "POST" and path == "/Ticket":
            self.n += 1
            self.t[self.n] = {"s": 2, "u": False, "l": inp.get("locations_id") or 0}
            return Resp(201, {"id": self.n}, m, url)
        if m == "GET" and mt and mt.group(2) and tk:
            return Resp(200, [{"type": 1}] + ([{"type": 2}] if tk["u"] else []), m, url)
        if m == "GET" and mt and tk:
            return Resp(200, {"status": tk["s"], "locations_id": tk["l"]}, m, url)
        if m == "POST" and path == "/Ticket_User":
            self.t[inp["tickets_id"]]["u"] = True
            return Resp(201, {"id": 1}, m, url)
        if m == "POST" and path == "/ITILSolution":
            self.t[inp["items_id"]]["s"] = 5
            return Resp(201, {"id": 1}, m, url)
        if m == "PUT" and mt and tk and "locations_id" in inp:
            tk["l"] = inp["locations_id"]
            return Resp(200, [{mt.group(1): True}], m, url)
        if m == "PUT" and mt and tk and "status" in inp:
            tk["s"] = inp["status"]
            return Resp(200, [{mt.group(1): True}], m, url)
        return Resp(200, {}, m, url)

    def get(self, u, **k):
        return self._go("GET", u, **k)

    def post(self, u, **k):
        return self._go("POST", u, **k)

    def put(self, u, **k):
        return self._go("PUT", u, **k)

    def novos(self):
        return [i for m, p, i in self.calls if m == "POST" and p == "/Ticket"]

    def acomp(self, t):
        return [i["content"] for m, p, i in self.calls if m == "POST" and p == "/Ticket/%d/ITILFollowup" % t]


def alerta(status, nome, site, fp, resumo="x", sev="critical", **extra):
    labels = {"alertname": nome, "site": site, "severity": sev, "grafana_folder": "GLPI Alerts"}
    labels.update(extra)
    return {"status": status, "fingerprint": fp, "labels": labels, "annotations": {"summary": resumo},
            "startsAt": "2026-10-20T09:00:00Z", "generatorURL": ""}


def enviar(mod, alertas):
    r = mod.app.test_client().post("/grafana-webhook", data=json.dumps({"alerts": alertas}),
                                   headers={"X-Webhook-Secret": "segredo", "Content-Type": "application/json"})
    assert r.status_code == 200, r.status_code


def estado(mod):
    return json.loads(mod.STATE_FILE.read_text(encoding="utf-8")) if mod.STATE_FILE.exists() else {}


def sites(mod):
    return sorted(k for k in estado(mod) if not k.startswith("_"))


# ---- 1) falha de backup: chamado BACKUP na categoria 43, localizacao HQ, titulo claro; 2a VM vira acompanhamento
mod = load()
g = FakeGLPI()
mod.requests = g
a1 = alerta("firing", "Backup - VM com problema", "BACKUP", "f-srv11", "srv11 (pve1): ultimo backup falhou. Ultimo backup bom: 30/09/2026 09:19",
            host="pve1", vm="srv11", problema="ultimo backup falhou")
a2 = alerta("firing", "Backup - VM com problema", "BACKUP", "f-srv-dc", "srv-dc (pve2): nunca teve backup", host="pve2", vm="srv-dc", problema="nunca teve backup")
enviar(mod, [a1])
n = g.novos()
print("BACKUP:", n[0]["name"], "| categoria", n[0]["itilcategories_id"], "| local", n[0]["locations_id"], "| urgencia", n[0]["urgency"])
assert len(n) == 1 and n[0]["name"] == "[Grafana] Incidente — BACKUP (backup Proxmox)", n
assert n[0]["itilcategories_id"] == 43 and n[0]["locations_id"] == 2 and n[0]["urgency"] == 5, n[0]
assert "srv11 (pve1)" in n[0]["content"], n[0]["content"]
g.calls.clear()
enviar(mod, [a1, a2])                                    # a1 repetido (o Grafana re-notifica) nao duplica; a2 vira acompanhamento
assert g.novos() == [] and len(g.acomp(101)) == 1 and "srv-dc" in g.acomp(101)[0] and sites(mod) == ["BACKUP"], (g.calls, sites(mod))
# normalizacao: so fecha quando a ULTIMA VM normaliza
g.calls.clear()
enviar(mod, [dict(a1, status="resolved")])
assert g.t[101]["s"] == 2, "nao pode fechar com a srv10 ainda com problema"
g.calls.clear()
enviar(mod, [dict(a2, status="resolved")])
assert g.t[101]["s"] == 6 and sites(mod) == [], (g.t, sites(mod))
print("   fechou sozinho com a ultima VM normalizada")
# falhou de novo dentro de 60 min: reabre o mesmo chamado
g.calls.clear()
enviar(mod, [a1])
assert g.novos() == [] and g.t[101]["s"] == 2 and sites(mod) == ["BACKUP"]

# ---- 2) infraestrutura Proxmox (coleta parada, sem dados): categoria 39
mod = load()
g = FakeGLPI()
mod.requests = g
sem_dados = alerta("firing", "Proxmox - Coleta parada (sem dados)", "INFRA", "f-sd", "Nenhum no Proxmox esta enviando CPU ao Zabbix ha mais de 10 minutos")
enviar(mod, [sem_dados])
n = g.novos()
assert len(n) == 1 and n[0]["name"] == "[Grafana] Incidente — INFRA (infraestrutura Proxmox)" and n[0]["itilcategories_id"] == 39 and n[0]["locations_id"] == 2, n
enviar(mod, [dict(sem_dados, status="resolved")])
assert g.t[101]["s"] == 6
print("INFRA: categoria 39, fechou ao normalizar")

# ---- 3) rede continua igual: categoria 49 e titulo sem sufixo
mod = load()
g = FakeGLPI()
mod.requests = g
enviar(mod, [alerta("firing", "Perda de Pacotes - LINKs", "BRANCH04", "f-br04", sev="warning")])
n = g.novos()
assert n[0]["name"] == "[Grafana] Incidente — BRANCH04" and n[0]["itilcategories_id"] == mod.GLPI_CATEGORY_ID == 49 and n[0]["urgency"] == 3, n
print("REDE: inalterada (categoria 49)")

# ---- 4) BACKUP/INFRA nao entram na contagem de avalanche: 9 sites de rede + BACKUP + INFRA + ERP = 12 "sites", sem emergencia
mod = load()
g = FakeGLPI()
mod.requests = g
for i in range(9):
    enviar(mod, [alerta("firing", "Perda", "SITE%d" % i, "n%d" % i, sev="critical")])
enviar(mod, [a1, sem_dados, alerta("firing", "ERP - CPU Alta", "ERP", "f-prot")])
assert mod.MASS_KEY not in estado(mod), "BACKUP/INFRA/ERP nao podem contar para a avalanche de rede"
assert len(g.novos()) == 12, len(g.novos())
# 10o site de rede: dispara a emergencia; depois disso um alerta de BACKUP continua com chamado proprio (nao e absorvido)
enviar(mod, [alerta("firing", "Perda", "SITE9", "n9", sev="critical")])
assert mod.MASS_KEY in estado(mod)
g.calls.clear()
enviar(mod, [alerta("firing", "Backup - Teste de restore falhou", "BACKUP", "f-rst", host="pve3", vm="srv35")])
assert g.novos() == [] and len(g.acomp(estado(mod)["BACKUP"]["ticket_id"])) == 1, "o BACKUP ja tinha chamado proprio: vira acompanhamento dele, nao do de emergencia"
enviar(mod, [alerta("firing", "Backup - Coleta do monitor parada", "INFRA", "f-inf2")])   # ja existe INFRA tambem
print("AVALANCHE: BACKUP/INFRA/ERP fora da contagem e fora do chamado de emergencia")

# ---- 5) a correlacao de tuneis e a regra dos demais sites nao mudaram (titulo do HQ com o sufixo da matriz)
mod = load()
g = FakeGLPI()
mod.requests = g
enviar(mod, [{"status": "firing", "fingerprint": "lk", "labels": {"alertname": "Perda de Pacotes - LINKs", "host": "FW HQ", "severity": "critical",
                                                                 "item": "SD-WAN [Default_AWS]:[wan2]: Packets loss"}, "annotations": {"summary": "x"}, "startsAt": "", "generatorURL": ""}])
assert g.novos()[0]["name"] == "[Grafana] Incidente — HQ (link da matriz e túneis)", g.novos()

print("TODOS OS TESTES PASSARAM")
