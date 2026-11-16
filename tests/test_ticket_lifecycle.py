"""Ciclo de vida do chamado (abrir, acompanhar, solucionar/fechar, reabrir), com um GLPI de mentira.

Uso: python test_ticket_lifecycle.py <grafana_glpi_webhook.py> [chaves-reais]
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
        mod.STATE_FILE.unlink()          # cada cenario comeca com o controle de incidentes vazio
    return mod


class Resp:
    def __init__(self, status=200, body=None, method="GET", url=""):
        self.status_code, self._body = status, body if body is not None else {}
        self.request = type("Req", (), {"method": method})()
        self.url = url
        self.text = json.dumps(self._body) if body is not None else ("" if status < 400 else '["ERROR_GLPI_ADD","motivo do GLPI"]')

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP %d" % self.status_code)

    def json(self):
        return self._body


class FakeGLPI:
    """GLPI de mentira. Registra as chamadas e imita a regra de producao: sem TECNICO (usuario) atribuido, o GLPI recusa a
    solucao (400) e ignora em silencio a mudanca de status para Solucionado/Fechado (200). 'falhas' =
    {(metodo, trecho_da_url[, status]): codigo}."""

    def __init__(self, falhas=None, regra_tecnico=True, tecnico_ja=False, ignora_status=False, regra_local=True, sem_local=False):
        self.calls, self.falhas, self.next_id = [], falhas or {}, 100
        self.regra_tecnico, self.tecnico_ja, self.ignora_status = regra_tecnico, tecnico_ja, ignora_status
        self.regra_local, self.sem_local = regra_local, sem_local      # sem_local: chamados de site fora do mapa nascem sem localizacao
        self.tickets = {}

    def _pendente(self, t):
        """Motivo pelo qual o GLPI de producao recusa solucionar/fechar (ou None)."""
        if self.regra_tecnico and not t["tecnico"]:
            return "Técnico atribuído é obrigatório antes do chamado ser solucionado/fechado"
        if self.regra_local and not t["loc"]:
            return "Localização é obrigatória antes que o chamado seja solucionado/fechado"
        return None

    def _go(self, method, url, **kw):
        path = url.split("/apirest.php")[1]
        self.calls.append((method, path, kw.get("json")))
        for (m, trecho, *so_status), st in self.falhas.items():
            if m == method and trecho in url and (not so_status or (kw.get("json") or {}).get("input", {}).get("status") == so_status[0]):
                if st == "false200":                                    # o GLPI aceita (200) mas marca false no corpo
                    return Resp(200, [{"101": False, "message": "nao permitido"}], method, url)
                return Resp(st, None, method, url)
        entrada = (kw.get("json") or {}).get("input", {})
        mt = re.match(r"^/Ticket/(\d+)(/Ticket_User)?$", path)
        tk = self.tickets.get(int(mt.group(1))) if mt else None
        if path.startswith("/initSession"):
            return Resp(200, {"session_token": "tok"}, method, url)
        if method == "POST" and path == "/Ticket":
            self.next_id += 1
            self.tickets[self.next_id] = {"status": 2, "tecnico": self.tecnico_ja, "loc": entrada.get("locations_id") or (0 if self.sem_local else 7)}
            return Resp(201, {"id": self.next_id}, method, url)
        if method == "GET" and mt and mt.group(2) and tk is not None:
            users = [{"type": 1, "users_id": 2}] + ([{"type": 2, "users_id": 9}] if tk["tecnico"] else [])
            return Resp(200, users, method, url)
        if method == "GET" and mt and tk is not None and not mt.group(2):
            return Resp(200, {"id": int(mt.group(1)), "status": tk["status"], "locations_id": tk["loc"]}, method, url)
        if method == "POST" and path == "/Ticket_User":
            if entrada.get("type") == 2:
                self.tickets[entrada["tickets_id"]]["tecnico"] = True
            return Resp(201, {"id": 1}, method, url)
        if method == "POST" and path == "/ITILSolution":
            t = self.tickets[entrada["items_id"]]
            motivo = self._pendente(t)
            if motivo:
                return Resp(400, ["ERROR_GLPI_ADD", motivo], method, url)
            t["status"] = 5
            return Resp(201, {"id": 1}, method, url)
        if method == "PUT" and mt and not mt.group(2) and tk is not None and "locations_id" in entrada:
            tk["loc"] = entrada["locations_id"]
            return Resp(200, [{mt.group(1): True, "message": ""}], method, url)
        if method == "PUT" and mt and not mt.group(2) and tk is not None and "status" in entrada:
            novo = entrada["status"]
            ignorar = self.ignora_status or (self._pendente(tk) is not None and novo in (5, 6))
            if not ignorar:
                tk["status"] = novo
            return Resp(200, [{mt.group(1): True, "message": ""}], method, url)    # 200 mesmo quando ignorou
        return Resp(200, {}, method, url)

    def get(self, url, **kw):
        return self._go("GET", url, **kw)

    def post(self, url, **kw):
        return self._go("POST", url, **kw)

    def put(self, url, **kw):
        return self._go("PUT", url, **kw)

    def ops(self):
        return [(m, p) for m, p, _ in self.calls if not p.startswith(("/initSession", "/killSession"))]


def send(mod, status, name, fp, site="TESTE", sev="warning"):
    body = {"alerts": [{"status": status, "fingerprint": fp, "labels": {"alertname": name, "site": site, "severity": sev},
                        "annotations": {"summary": "x"}, "startsAt": "2026-10-19T10:00:00Z", "generatorURL": ""}]}
    c = mod.app.test_client()
    r = c.post("/grafana-webhook", data=json.dumps(body), headers={"X-Webhook-Secret": "segredo", "Content-Type": "application/json"})
    assert r.status_code == 200, r.status_code


def state(mod):
    return json.loads(mod.STATE_FILE.read_text(encoding="utf-8")) if mod.STATE_FILE.exists() else {}


# ---- 1) ciclo normal: abre, normaliza (fecha), reincide dentro da janela (reabre), normaliza de novo
mod = load()
g = FakeGLPI()
mod.requests = g
send(mod, "firing", "Perda de pacote", "fp1")
assert ("POST", "/Ticket") in g.ops() and state(mod)["TESTE"]["ticket_id"] == 101
g.calls.clear()
send(mod, "resolved", "Perda de pacote", "fp1")
ops = g.ops()
print("NORMALIZOU:", ops)
assert ops == [("POST", "/Ticket/101/ITILFollowup"), ("GET", "/Ticket/101/Ticket_User"), ("POST", "/Ticket_User"), ("GET", "/Ticket/101"),
               ("POST", "/ITILSolution"), ("PUT", "/Ticket/101"), ("GET", "/Ticket/101")], ops
assert g.tickets[101]["status"] == 6 and g.tickets[101]["tecnico"], g.tickets            # fechou DE VERDADE (a regra de producao exige tecnico)
tu = [b for m, p, b in g.calls if p == "/Ticket_User"][0]["input"]
assert tu == {"tickets_id": 101, "users_id": 2, "type": 2}, tu                            # conta de servico como tecnico (type 2 = atribuido)
sol = [b for m, p, b in g.calls if p == "/ITILSolution"][0]["input"]
assert sol["itemtype"] == "Ticket" and sol["items_id"] == 101 and "TESTE" in sol["content"]
assert [b for m, p, b in g.calls if m == "PUT"][0] == {"input": {"status": 6}}
st = state(mod)
assert "TESTE" not in st and st["_recently_closed"]["TESTE"]["ticket_id"] == 101

g.calls.clear()
send(mod, "firing", "Perda de pacote", "fp1")
ops = g.ops()
print("REINCIDIU:", ops)
assert ops == [("PUT", "/Ticket/101"), ("GET", "/Ticket/101"), ("POST", "/Ticket/101/ITILFollowup")], ops   # reabre (e confere) ANTES do acompanhamento
assert [b for m, p, b in g.calls if m == "PUT"][0] == {"input": {"status": 2}}
assert state(mod)["TESTE"]["ticket_id"] == 101 and "TESTE" not in state(mod).get("_recently_closed", {})
g.calls.clear()
send(mod, "resolved", "Perda de pacote", "fp1")
assert ("PUT", "/Ticket/101") in g.ops() and ("POST", "/ITILSolution") in g.ops()

# ---- 2) varios sintomas: so fecha quando o ULTIMO normaliza
mod = load()
g = FakeGLPI()
mod.requests = g
send(mod, "firing", "A", "fa")
send(mod, "firing", "B", "fb")
g.calls.clear()
send(mod, "resolved", "A", "fa")
assert ("POST", "/ITILSolution") not in g.ops() and not [1 for m, p in g.ops() if m == "PUT"], g.ops()
g.calls.clear()
send(mod, "resolved", "B", "fb")
assert ("POST", "/ITILSolution") in g.ops() and ("PUT", "/Ticket/101") in g.ops()

# ---- 3) fora da janela: chamado novo, sem reabrir o antigo
mod = load()
g = FakeGLPI()
mod.requests = g
send(mod, "firing", "A", "fa")
send(mod, "resolved", "A", "fa")
st = state(mod)
st["_recently_closed"]["TESTE"]["closed_at"] = (datetime.utcnow() - timedelta(minutes=61)).isoformat()
mod.STATE_FILE.write_text(json.dumps(st), encoding="utf-8")
g.calls.clear()
send(mod, "firing", "A", "fa")
assert ("POST", "/Ticket") in g.ops() and not [1 for m, p in g.ops() if m == "PUT"], g.ops()
assert state(mod)["TESTE"]["ticket_id"] == 102

class Captura(logging.Handler):
    def __init__(self):
        super().__init__()
        self.msgs = []

    def emit(self, record):
        self.msgs.append(self.format(record) + (" | " + str(record.exc_info[1]) if record.exc_info else ""))


cap = Captura()
logging.getLogger().addHandler(cap)
logging.getLogger().setLevel(logging.INFO)

# ---- 4) GLPI recusa a SOLUCAO (400, como em producao): o log traz o motivo e o webhook fecha pelo status (5, depois 6)
mod = load()
g = FakeGLPI(falhas={("POST", "/ITILSolution"): 400})
mod.requests = g
send(mod, "firing", "A", "fa")
g.calls.clear()
cap.msgs.clear()
send(mod, "resolved", "A", "fa")
puts = [b["input"]["status"] for m, p, b in g.calls if m == "PUT"]
assert puts == [5, 6], puts
assert any("recusou registrar a solucao" in x and "motivo do GLPI" in x and "400" in x for x in cap.msgs), cap.msgs      # o motivo aparece no log
assert "TESTE" not in state(mod) and "TESTE" in state(mod)["_recently_closed"]

# ---- 4b) recusa a solucao E o status direto: nao derruba, o site zera, o aviso fica no log (sem tentar o 6)
mod = load()
g = FakeGLPI(falhas={("POST", "/ITILSolution"): 400, ("PUT", "/Ticket", 5): "false200"})
mod.requests = g
send(mod, "firing", "A", "fa")
g.calls.clear()
cap.msgs.clear()
send(mod, "resolved", "A", "fa")
assert [b["input"]["status"] for m, p, b in g.calls if m == "PUT"] == [5]
assert any("Falha ao encerrar automaticamente" in x and "nao permitido" in x for x in cap.msgs), cap.msgs                 # false no corpo (HTTP 200) conta como erro
assert ("POST", "/Ticket/101/ITILFollowup") in g.ops() and "TESTE" not in state(mod) and "TESTE" in state(mod)["_recently_closed"]

# ---- 4d) caso real de producao: o GLPI IGNORA o status (200) sem tecnico; sem a protecao o log diria "fechado" sem estar
mod = load()
g = FakeGLPI(ignora_status=True)
mod.requests = g
send(mod, "firing", "A", "fa")
cap.msgs.clear()
send(mod, "resolved", "A", "fa")
assert any("nao aplicou o status esperado" in x and "esperado 6, atual" in x for x in cap.msgs), cap.msgs
assert not any("solucionado e fechado automaticamente" in x for x in cap.msgs), "nao pode dizer que fechou quando nao fechou"
assert g.tickets[101]["status"] != 6

# ---- 4e) ja ha tecnico atribuido (alguem assumiu o chamado): nao atribui a conta de servico por cima
mod = load()
g = FakeGLPI(tecnico_ja=True)
mod.requests = g
send(mod, "firing", "A", "fa")
g.calls.clear()
send(mod, "resolved", "A", "fa")
assert ("POST", "/Ticket_User") not in g.ops() and g.tickets[101]["status"] == 6, g.ops()

# ---- 4f) nao consegue atribuir o tecnico: loga o motivo, nao tenta a solucao, nao derruba o webhook
mod = load()
g = FakeGLPI(falhas={("POST", "/Ticket_User"): 403})
mod.requests = g
send(mod, "firing", "A", "fa")
g.calls.clear()
cap.msgs.clear()
send(mod, "resolved", "A", "fa")
assert ("POST", "/ITILSolution") not in g.ops() and any("Falha ao encerrar automaticamente" in x and "403" in x for x in cap.msgs), cap.msgs
assert "TESTE" not in state(mod)

# ---- 4c) a solucao funciona mas o 6 e recusado: loga, nao derruba
mod = load()
g = FakeGLPI(falhas={("PUT", "/Ticket", 6): 403})
mod.requests = g
send(mod, "firing", "A", "fa")
cap.msgs.clear()
send(mod, "resolved", "A", "fa")
assert any("Falha ao encerrar automaticamente" in x and "403" in x for x in cap.msgs), cap.msgs

# ---- 5) reabrir falha (ex: GLPI recusa): abre chamado NOVO e nao perde o alerta
mod = load()
g = FakeGLPI()
mod.requests = g
send(mod, "firing", "A", "fa")
send(mod, "resolved", "A", "fa")
g.falhas = {("PUT", "/Ticket/101"): 403}
g.calls.clear()
send(mod, "firing", "A", "fa")
assert ("POST", "/Ticket") in g.ops(), g.ops()
assert state(mod)["TESTE"]["ticket_id"] == 102

# ---- 5b) o GLPI "aceita" (200) mas ignora a reabertura: o chamado continua Fechado => abre chamado NOVO, nao perde o alerta
mod = load()
g = FakeGLPI()
mod.requests = g
send(mod, "firing", "A", "fa")
send(mod, "resolved", "A", "fa")
assert g.tickets[101]["status"] == 6
g.ignora_status = True
g.calls.clear()
cap.msgs.clear()
send(mod, "firing", "A", "fa")
assert ("POST", "/Ticket") in g.ops() and state(mod)["TESTE"]["ticket_id"] == 102, g.ops()
assert any("Nao consegui reabrir" in x and "continua com status 6" in x for x in cap.msgs), cap.msgs
# reabertura normal: o chamado fechado volta a "Em atendimento" de verdade
mod = load()
g = FakeGLPI()
mod.requests = g
send(mod, "firing", "A", "fa")
send(mod, "resolved", "A", "fa")
send(mod, "firing", "A", "fa")
assert g.tickets[101]["status"] == 2 and state(mod)["TESTE"]["ticket_id"] == 101

# ---- 5c) caso real de producao (3a rodada): site fora do mapa nasce SEM localizacao e o GLPI exige localizacao para fechar
mod = load()
g = FakeGLPI(sem_local=True)
mod.requests = g
send(mod, "firing", "A", "fa")                               # site TESTE: fora do mapa
assert g.tickets[101]["loc"] == 0
g.calls.clear()
send(mod, "resolved", "A", "fa")
assert g.tickets[101]["status"] == 6 and g.tickets[101]["loc"] == 2, g.tickets                 # completou com a localizacao padrao (HQ)
assert [b for m, p, b in g.calls if m == "PUT" and "locations_id" in b["input"]] == [{"input": {"locations_id": 2}}]
# HQ_SWITCHES e ERP agora ja nascem com localizacao (HQ = 2): nada a completar ao fechar
for site_novo in ("HQ_SWITCHES", "ERP"):
    mod = load()
    g = FakeGLPI(sem_local=True)
    mod.requests = g
    send(mod, "firing", "A", "fm", site=site_novo)
    criado = [b for m, p, b in g.calls if m == "POST" and p == "/Ticket"][0]["input"]
    assert criado["locations_id"] == 2, (site_novo, criado)
    g.calls.clear()
    send(mod, "resolved", "A", "fm", site=site_novo)
    assert g.tickets[101]["status"] == 6 and not [1 for m, p, b in g.calls if m == "PUT" and "locations_id" in b["input"]]
# site mapeado mantem a propria localizacao (BRANCH01 = 6)
mod = load()
g = FakeGLPI(sem_local=True)
mod.requests = g
send(mod, "firing", "A", "ft", site="BRANCH01")
send(mod, "resolved", "A", "ft", site="BRANCH01")
assert g.tickets[101]["loc"] == 6 and g.tickets[101]["status"] == 6
# nao consegue completar a localizacao: loga o motivo, nao tenta a solucao, nao derruba o webhook
mod = load()
g = FakeGLPI(sem_local=True)
mod.requests = g
send(mod, "firing", "A", "fa")
g.falhas = {("PUT", "/Ticket/101"): 403}                     # a partir daqui o GLPI recusa qualquer PUT no chamado
g.calls.clear()
cap.msgs.clear()
send(mod, "resolved", "A", "fa")
assert ("POST", "/ITILSolution") not in g.ops() and any("Falha ao encerrar automaticamente" in x and "403" in x for x in cap.msgs), cap.msgs
assert "TESTE" not in state(mod)

# ---- 6) CLOSE_TICKET_ON_RESOLVE = False: so "Solucionado"
mod = load()
mod.CLOSE_TICKET_ON_RESOLVE = False
g = FakeGLPI()
mod.requests = g
send(mod, "firing", "A", "fa")
g.calls.clear()
send(mod, "resolved", "A", "fa")
assert ("POST", "/ITILSolution") in g.ops() and not [1 for m, p in g.ops() if m == "PUT"], g.ops()

# ---- 7) evento de avalanche: fecha o chamado de emergencia ao normalizar tudo
mod = load()
g = FakeGLPI()
mod.requests = g
for i in range(12):                      # os 9 primeiros abrem chamado proprio; o 10o dispara a avalanche; os demais viram acompanhamento
    send(mod, "firing", "Perda", "f%d" % i, site="SITE%d" % i, sev="critical")
assert "_mass" in state(mod)
mass_id = state(mod)["_mass"]["ticket_id"]
assert mass_id == 110 and len(state(mod)["_mass"]["active"]) == 3          # SITE9, SITE10 e SITE11 no chamado de emergencia
g.calls.clear()
for i in range(12):
    send(mod, "resolved", "Perda", "f%d" % i, site="SITE%d" % i, sev="critical")
sol = [(m, p) for m, p in g.ops() if p == "/ITILSolution"]
puts = [p for m, p in g.ops() if m == "PUT"]
assert len(sol) == 10 and sorted(puts) == sorted("/Ticket/%d" % t for t in range(101, 111)), (len(sol), puts)   # 9 individuais + 1 de emergencia, cada um uma vez
assert puts.count("/Ticket/%d" % mass_id) == 1, "o chamado de emergencia so fecha quando o ULTIMO site normaliza"
assert "_mass" not in state(mod)

# ---- 8) o que nao mudou: segredo errado continua 401
mod = load()
mod.requests = FakeGLPI()
r = mod.app.test_client().post("/grafana-webhook", data="{}", headers={"X-Webhook-Secret": "errado"})
assert r.status_code == 401

print("TODOS OS TESTES PASSARAM")
