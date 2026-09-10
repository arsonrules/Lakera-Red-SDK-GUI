"""Full-scenario test for the Lakera Red Runner.

Spins up real local endpoints (http, https, ws, wss -- the TLS ones behind a
self-signed cert) and a mock Red relay that speaks the SDK's wire protocol, then
drives the service end to end:

  * 4 schemes x 4 auth methods through /api/probe
  * TLS: self-signed accepted with verify off, rejected with verify on
  * response_path extraction and {{messages}} multi-turn history
  * bad input rejected at the boundary
  * full scans via /api/scans: app-context target, recon-discovered target,
    reused target by id, refresh_recon, crescendo over ws, smoke, custom
    objectives, and a failing target that surfaces the error

Run:  .venv/bin/python test_all.py
"""

from __future__ import annotations

import asyncio
import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from fastapi import APIRouter, FastAPI, Request, Response, WebSocket

import app as app_module
import app as service
from targets import TargetConfig, extract, open_session
from tls_doctor import read_ca_pems

HTTP_PORT, TLS_PORT, RELAY_PORT, CA_PORT = 8801, 8802, 8803, 8804
BEARER, API_KEY, USER, PASSWORD = "tok-bearer-123", "key-abc-789", "alice", "s3cr3t"

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASSED.append(name) if cond else FAILED.append((name, detail)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{'' if cond else '  <- ' + detail}")


# --------------------------------------------------------------- echo target app


def auth_marker(headers) -> str:
    """Report which credential the target actually received, so tests can prove it arrived."""
    authz = headers.get("authorization", "")
    if authz.startswith("Bearer "):
        return "bearer:" + authz[7:]
    if authz.startswith("Basic "):
        return "basic:" + base64.b64decode(authz[6:]).decode()
    for name, value in headers.items():
        if name.lower().startswith("x-") and name.lower().endswith("-key"):
            return f"apikey:{name.lower()}:{value}"
    return "none"


def build_echo_app() -> FastAPI:
    echo = FastAPI()

    @echo.post("/chat")
    async def chat(request: Request) -> dict[str, Any]:
        body = await request.json()
        text = body.get("message") or (body.get("messages") or [{}])[-1].get("content", "")
        turns = len(body.get("messages") or [])
        return {
            "choices": [{"message": {"content": f"echo:{text}|auth={auth_marker(request.headers)}"}}],
            "turns": turns,
        }

    @echo.post("/refuse")
    async def refuse() -> Response:
        return Response('{"error":"nope"}', status_code=500, media_type="application/json")

    @echo.websocket("/ws")
    async def ws(sock: WebSocket) -> None:
        await sock.accept()
        marker, turns = auth_marker(sock.headers), 0
        try:
            while True:
                raw = await sock.receive_text()
                turns += 1
                try:
                    text = json.loads(raw)
                    text = text[-1]["content"] if isinstance(text, list) else str(text)
                except ValueError:
                    text = raw
                await sock.send_text(
                    json.dumps({"reply": f"echo:{text}|auth={marker}|turn={turns}", "turns": turns})
                )
        except Exception:
            return

    return echo


# --------------------------------------------------------------- mock Red relay


class MockRelay:
    """Minimal stand-in for red-webhooks.lakera.ai, enough to drive the SDK."""

    def __init__(self) -> None:
        self.targets: dict[str, dict[str, Any]] = {}
        self.scans: dict[str, dict[str, Any]] = {}
        self.queues: dict[str, list[dict[str, Any]]] = {}
        self.pending: dict[str, dict[str, Any]] = {}  # session_id -> scope state
        self.responses: dict[str, list[str]] = {}
        self.errors: dict[str, list[str]] = {}
        self.auth_seen: list[str] = []
        self.turns_per_session = 1

    def router(self) -> APIRouter:
        r = APIRouter()

        @r.post("/relay/targets")
        async def create_target(request: Request) -> dict[str, Any]:
            self.auth_seen.append(request.headers.get("authorization", ""))
            body = await request.json()
            name = body["name"]
            tid = next(
                (i for i, t in self.targets.items() if t["name"] == name), f"target_{len(self.targets)+1}"
            )
            existing = self.targets.get(tid, {})
            self.targets[tid] = {
                "targetId": tid,
                "name": name,
                "recon": body.get("appContext") or existing.get("recon"),
                "groundTruth": body.get("groundTruth") or existing.get("groundTruth"),
            }
            return self.targets[tid]

        @r.get("/relay/targets/{tid}")
        async def get_target(tid: str) -> Any:
            if tid not in self.targets:
                return Response('{"error":"not found"}', 404, media_type="application/json")
            return self.targets[tid]

        @r.patch("/relay/targets/{tid}")
        async def update_target(tid: str, request: Request) -> Any:
            body = await request.json()
            t = self.targets[tid]
            t.update({k: v for k, v in
                      (("name", body.get("name")), ("recon", body.get("appContext")),
                       ("groundTruth", body.get("groundTruth"))) if v})
            return t

        @r.post("/relay/targets/{tid}/recon")
        async def start_recon(tid: str) -> dict[str, str]:
            recon_id = f"recon_{tid}"
            self._enqueue(recon_id, sessions=1, turns=2, prefix="recon-probe",
                          end_payload={"appDescription": "discovered app",
                                       "allowedActions": "chat", "forbiddenActions": "leak"})
            return {"reconId": recon_id}

        @r.post("/relay/scans")
        async def create_scan(request: Request) -> dict[str, str]:
            body = await request.json()
            sid = f"scan_{len(self.scans)+1}"
            objectives = body.get("objectiveIds") or ["default.objective.1"]
            objectives += [o["key"] for o in body.get("customObjectives") or []]
            if body["strategyName"] == "smoke":
                objectives = ["smoke.probe.1"]
            self.scans[sid] = {"objectives": objectives, "body": body}
            return {"scanId": sid, "dashboardLink": f"http://localhost/scans/{sid}"}

        @r.post("/relay/scans/{sid}/start")
        async def start_scan(sid: str) -> dict[str, bool]:
            objectives = self.scans[sid]["objectives"]
            self._enqueue(sid, sessions=len(objectives), turns=self.turns_per_session,
                          prefix="attack", labels=objectives)
            return {"ok": True}

        @r.get("/relay/messages")
        async def poll(messageScopeId: str, targetId: str) -> Any:
            queue = self.queues.get(messageScopeId, [])
            if not queue:
                return Response(status_code=204)
            head = queue[0]
            if head.get("gate") and self.pending.get(head["gate"], {}).get("awaiting"):
                return Response(status_code=204)  # wait for the handler's reply first
            return queue.pop(0)["message"]

        @r.post("/relay/sessions/{session_id}/response")
        async def submit(session_id: str, request: Request) -> dict[str, bool]:
            body = await request.json()
            self.responses.setdefault(session_id, []).append(body["message"])
            self.pending.setdefault(session_id, {})["awaiting"] = False
            return {"ok": True}

        @r.post("/relay/sessions/{session_id}/error")
        async def submit_error(session_id: str, request: Request) -> dict[str, bool]:
            body = await request.json()
            self.errors.setdefault(session_id, []).append(body["message"])
            self.pending.setdefault(session_id, {})["awaiting"] = False
            return {"ok": True}

        @r.get("/relay/scans/{sid}/results")
        async def results(sid: str) -> dict[str, Any]:
            entries = []
            for i, objective in enumerate(self.scans[sid]["objectives"]):
                replies = self.responses.get(f"{sid}-s{i}", [])
                error = (self.errors.get(f"{sid}-s{i}") or [None])[0]
                entries.append({
                    "objectiveId": objective,
                    "conversation": [{"role": "assistant", "content": r} for r in replies],
                    "evaluation": None if error else {
                        "attackSuccessIndicator": "true" if i == 0 else "false",
                        "attackSuccessScore": 5 if i == 0 else 0,
                        "explanation": "mock verdict",
                    },
                    "isSuccessful": error is None and i == 0,
                    **({"error": error} if error else {}),
                })
            return {"ready": True, "results": entries}

        return r

    def _enqueue(self, scope: str, *, sessions: int, turns: int, prefix: str,
                 labels: list[str] | None = None, end_payload: dict[str, Any] | None = None) -> None:
        queue: list[dict[str, Any]] = []
        for turn in range(turns):
            for i in range(sessions):
                sid = f"{scope}-s{i}"
                label = (labels[i] if labels else scope)
                queue.append({"gate": sid if turn else None, "message": {
                    "sessionId": sid, "payload": f"{prefix} {label} turn{turn+1}"}})
        for i in range(sessions):
            sid = f"{scope}-s{i}"
            queue.append({"gate": sid, "message": {"type": "end_session", "sessionId": sid}})
        queue.append({"gate": f"{scope}-s0", "message": {"type": "end_scope",
                                                        **({"payload": end_payload} if end_payload else {})}})
        self.queues[scope] = queue
        for i in range(sessions):
            self.pending[f"{scope}-s{i}"] = {"awaiting": False}


# --------------------------------------------------------------- server plumbing


class Server(uvicorn.Server):
    def install_signal_handlers(self) -> None:  # running inside our own loop
        pass


async def serve(app_obj, port: int, **kwargs) -> tuple[Server, asyncio.Task]:
    server = Server(uvicorn.Config(app_obj, host="127.0.0.1", port=port, log_level="error", **kwargs))
    task = asyncio.create_task(server.serve())
    for _ in range(200):
        if server.started:
            return server, task
        await asyncio.sleep(0.05)
    raise RuntimeError(f"server on {port} did not start")


def make_cert(tmp: Path) -> tuple[str, str]:
    key, cert = tmp / "key.pem", tmp / "cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(cert), "-days", "2", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, capture_output=True,
    )
    return str(key), str(cert)


def make_ca_signed(tmp: Path) -> tuple[str, str, str]:
    """A private root CA plus a leaf it signed -- the corporate-proxy / internal-PKI shape.

    The server sends only the leaf, so verification fails with 'unable to get
    local issuer certificate' rather than the self-signed error.
    """
    run = lambda *a: subprocess.run(list(a), check=True, capture_output=True)
    ca_key, ca_crt = tmp / "ca.key", tmp / "ca.crt"
    leaf_key, leaf_csr, leaf_crt = tmp / "leaf.key", tmp / "leaf.csr", tmp / "leaf.crt"
    ext = tmp / "ext.cnf"
    ext.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n")
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key),
        "-out", str(ca_crt), "-days", "2", "-subj", "/CN=Acme Corporate Root CA",
        "-addext", "basicConstraints=critical,CA:TRUE")
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(leaf_key),
        "-out", str(leaf_csr), "-subj", "/CN=localhost")
    run("openssl", "x509", "-req", "-in", str(leaf_csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
        "-CAcreateserial", "-out", str(leaf_crt), "-days", "2", "-extfile", str(ext))
    return str(leaf_key), str(leaf_crt), str(ca_crt)


# --------------------------------------------------------------- scenarios

AUTHS = {
    "none": ({"auth_type": "none"}, "auth=none"),
    "bearer": ({"auth_type": "bearer", "token": BEARER}, f"auth=bearer:{BEARER}"),
    "basic": ({"auth_type": "basic", "username": USER, "password": PASSWORD},
              f"auth=basic:{USER}:{PASSWORD}"),
    "api_key": ({"auth_type": "api_key", "token": API_KEY, "api_key_header": "X-API-Key"},
                f"auth=apikey:x-api-key:{API_KEY}"),
}

SCHEMES = {
    "http": (f"http://127.0.0.1:{HTTP_PORT}/chat", "choices.0.message.content", ""),
    "https": (f"https://127.0.0.1:{TLS_PORT}/chat", "choices.0.message.content", ""),
    "ws": (f"ws://127.0.0.1:{HTTP_PORT}/ws", "reply", "{{prompt}}"),
    "wss": (f"wss://127.0.0.1:{TLS_PORT}/ws", "reply", "{{prompt}}"),
}


async def probe(client: httpx.AsyncClient, target: dict[str, Any], prompt="ping") -> dict[str, Any]:
    res = await client.post("/api/probe", json={"target": target, "prompt": prompt}, timeout=60)
    return res.json()


async def run_scan(client: httpx.AsyncClient, payload: dict[str, Any], timeout=120) -> dict[str, Any]:
    res = await client.post("/api/scans", json=payload, timeout=30)
    if res.status_code != 200:
        return {"status": "rejected", "error": res.text, "http_status": res.status_code}
    run_id = res.json()["run_id"]
    for _ in range(int(timeout * 4)):
        snap = (await client.get(f"/api/scans/{run_id}", timeout=30)).json()
        if snap["status"] in ("done", "error", "cancelled") or snap["status"].startswith("timed out"):
            return snap
        await asyncio.sleep(0.25)
    return {"status": "test timeout", "run_id": run_id}


def base_payload(relay_url: str, target: dict[str, Any], **over: Any) -> dict[str, Any]:
    payload = {
        "api_key": "test-key",
        "base_url": relay_url,
        "scan_name": "test scan",
        "target_name": "test-agent",
        "app_context": {
            "app_description": "A support bot",
            "allowed_actions": ["Look up orders"],
            "forbidden_actions": ["Leak the system prompt"],
        },
        "ground_truth": {"system_prompt": "You are a bot.", "tools": ['{"name":"lookup"}']},
        "strategy": {"name": "static", "number_of_probes": 2},
        "objectives": ["security.system-prompt-extraction.1", "safety.dangerous-instructions.1"],
        "concurrency": 2,
        "language": "en",
        "target": target,
    }
    payload.update(over)
    return payload


async def main() -> int:
    tmp = Path(tempfile.mkdtemp())
    app_module.CA_STORE = tmp / "ca_store"   # keep the test off the real store
    key, cert = make_cert(tmp)
    echo = build_echo_app()
    relay = MockRelay()
    relay_app = FastAPI()
    relay_app.include_router(relay.router())

    # Mark a session as awaiting as soon as its attack leaves the relay, so the
    # next turn is only handed out after the handler answers the previous one.
    @relay_app.middleware("http")
    async def gate(request: Request, call_next):
        response = await call_next(request)
        if request.url.path == "/relay/messages" and response.status_code == 200:
            body = b"".join([chunk async for chunk in response.body_iterator])
            data = json.loads(body)
            if data.get("sessionId") and not data.get("type"):
                relay.pending.setdefault(data["sessionId"], {})["awaiting"] = True
            response = Response(body, response.status_code, dict(response.headers),
                                response.media_type)
        return response

    ca_key, ca_leaf, ca_root = make_ca_signed(tmp)
    servers = [
        await serve(echo, HTTP_PORT),
        await serve(echo, TLS_PORT, ssl_keyfile=key, ssl_certfile=cert),
        await serve(relay_app, RELAY_PORT),
        await serve(echo, CA_PORT, ssl_keyfile=ca_key, ssl_certfile=ca_leaf),
    ]
    relay_url = f"http://127.0.0.1:{RELAY_PORT}"
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=service.app), base_url="http://runner"
    )

    try:
        print("\n[1] transport x auth matrix (4 schemes x 4 auth methods)")
        for scheme, (url, path, body) in SCHEMES.items():
            for auth_name, (auth, marker) in AUTHS.items():
                target = {"url": url, "response_path": path, "body_template": body,
                          "verify_tls": False, **auth}
                out = await probe(client, target, prompt="hello")
                ok = out.get("ok") and "echo:hello" in out.get("reply", "") \
                    and marker in out.get("reply", "")
                check(f"{scheme:5} + {auth_name:8}", ok, json.dumps(out)[:220])

        print("\n[2] TLS handling")
        for scheme, url in (("https", SCHEMES["https"][0]), ("wss", SCHEMES["wss"][0])):
            body = "" if scheme == "https" else "{{prompt}}"
            path = "choices.0.message.content" if scheme == "https" else "reply"
            off = await probe(client, {"url": url, "response_path": path, "body_template": body,
                                       "verify_tls": False})
            on = await probe(client, {"url": url, "response_path": path, "body_template": body,
                                      "verify_tls": True})
            check(f"{scheme}: self-signed cert accepted with verify off", bool(off.get("ok")),
                  json.dumps(off)[:220])
            check(f"{scheme}: self-signed cert rejected with verify on", not on.get("ok"),
                  json.dumps(on)[:220])

        print("\n[2b] certificate trust: private CA, bundles, and the diagnosis")
        ca_https = f"https://127.0.0.1:{CA_PORT}/chat"
        ca_wss = f"wss://127.0.0.1:{CA_PORT}/ws"

        untrusted = await probe(client, {"url": ca_https, "verify_tls": True})
        check("private-CA cert rejected when its root is not trusted",
              not untrusted.get("ok") and "unable to get local issuer" in untrusted.get("error", ""),
              json.dumps(untrusted)[:220])
        check("the rejection explains the cause and the fix",
              "TLS-inspection proxy" in (untrusted.get("tls_hint") or "")
              or "CA bundle" in (untrusted.get("tls_hint") or ""), str(untrusted.get("tls_hint")))

        for scheme, url, path, body in (("https", ca_https, "choices.0.message.content", ""),
                                        ("wss", ca_wss, "reply", "{{prompt}}")):
            out = await probe(client, {"url": url, "response_path": path, "body_template": body,
                                       "ca_bundle": ca_root})
            check(f"{scheme}: verification passes with the issuing CA supplied",
                  out.get("ok") and "echo:" in out.get("reply", ""), json.dumps(out)[:220])

        wrong = await probe(client, {"url": ca_https, "ca_bundle": cert})
        check("a CA bundle that does not sign the cert still fails",
              not wrong.get("ok"), json.dumps(wrong)[:200])
        gone = await probe(client, {"url": ca_https, "ca_bundle": "/no/such/ca.pem"})
        check("a missing CA bundle path is reported clearly",
              not gone.get("ok") and "CA bundle not found" in gone.get("error", ""),
              json.dumps(gone)[:200])

        # https and wss must agree: one shared trust store, no transport surprises.
        pairs = []
        for url, path, body in ((ca_https, "choices.0.message.content", ""),
                                (ca_wss, "reply", "{{prompt}}")):
            pairs.append((await probe(client, {"url": url, "response_path": path,
                                               "body_template": body, "verify_tls": True})).get("ok"))
        check("https and wss agree on trust (no transport-dependent verdict)",
              pairs[0] == pairs[1] is False, str(pairs))

        async def diagnose(target):
            return (await client.post("/api/tls-check", json={"target": target}, timeout=60)).json()

        d = await diagnose({"url": ca_https})
        check("diagnosis names the untrusted issuer", d.get("verdict") == "untrusted-issuer"
              and "Acme Corporate Root CA" == (d.get("certificate") or {}).get("issuer"),
              json.dumps(d)[:300])
        check("diagnosis reports every trust store it tried",
              len(d.get("stores") or []) >= 2 and not any(s["accepts"] for s in d["stores"]),
              str(d.get("stores"))[:200])
        d = await diagnose({"url": ca_https, "ca_bundle": ca_root})
        check("diagnosis clears the endpoint once the right CA is supplied",
              d.get("verdict") == "verifiable", json.dumps(d)[:220])
        d = await diagnose({"url": f"https://127.0.0.1:{TLS_PORT}/chat"})
        check("diagnosis identifies a self-signed certificate", d.get("verdict") == "self-signed",
              json.dumps(d)[:220])
        d = await diagnose({"url": f"https://127.0.0.1:{HTTP_PORT}/chat"})
        check("diagnosis separates 'not TLS' from a trust problem",
              d.get("verdict") == "no-handshake", json.dumps(d)[:220])
        d = await diagnose({"url": SCHEMES["http"][0]})
        check("diagnosis declines a non-TLS scheme", d.get("verdict") == "not-tls",
              json.dumps(d)[:220])
        d = await diagnose({"url": ca_wss})
        check("diagnosis works for wss as well as https",
              d.get("verdict") == "untrusted-issuer", json.dumps(d)[:220])

        print("\n[2c] CA bundles: directories, uploads, and the store")
        import shutil

        ca_dir = tmp / "cadir"
        ca_dir.mkdir(exist_ok=True)
        shutil.copy(ca_root, ca_dir / "acme-root.pem")
        subprocess.run(["openssl", "x509", "-in", ca_root, "-outform", "DER",
                        "-out", str(ca_dir / "acme-root.der")], check=True, capture_output=True)

        pems, names = read_ca_pems(str(ca_dir))
        check("a plain directory of certs is read (capath would silently trust nothing)",
              len(pems) == 2 and names.count("Acme Corporate Root CA") == 2, str(names))
        check("DER files in a directory are accepted alongside PEM",
              all("BEGIN CERTIFICATE" in p for p in pems), "")

        out = await probe(client, {"url": ca_https, "ca_bundle": str(ca_dir)})
        check("a directory works as a CA bundle end to end", out.get("ok"), json.dumps(out)[:200])

        for junk, label in ((str(tmp / "junk.txt"), "a non-certificate file"),
                            (ca_key, "a private key")):
            Path(tmp / "junk.txt").write_text("definitely not a certificate")
            got = await client.post("/api/ca/inspect", json={"path": junk})
            check(f"inspect rejects {label}", got.json().get("ok") is False, got.text[:140])

        insp = (await client.post("/api/ca/inspect", json={"path": str(ca_dir)})).json()
        check("inspect lists the subjects in a directory",
              insp.get("ok") and insp["count"] == 2, json.dumps(insp)[:200])

        pasted = await client.post("/api/ca", json={"name": "corp root",
                                                    "pem": Path(ca_root).read_text()})
        stored = pasted.json()
        check("a pasted PEM is stored and described",
              pasted.status_code == 200 and stored["subjects"] == ["Acme Corporate Root CA"],
              pasted.text[:200])

        der_b64 = base64.b64encode((ca_dir / "acme-root.der").read_bytes()).decode()
        up = await client.post("/api/ca", json={"name": "acme.der", "data_b64": der_b64})
        check("an uploaded DER file is normalised to PEM and stored",
              up.status_code == 200 and up.json()["count"] == 1
              and "BEGIN CERTIFICATE" in Path(up.json()["path"]).read_text(), up.text[:200])

        out = await probe(client, {"url": ca_https, "ca_bundle": stored["path"]})
        check("an uploaded bundle verifies the endpoint", out.get("ok"), json.dumps(out)[:200])

        evil = await client.post("/api/ca", json={"name": "../../../../tmp/evil",
                                                  "pem": Path(ca_root).read_text()})
        check("upload names cannot escape the CA store",
              Path(evil.json()["path"]).parent == app_module.CA_STORE, evil.text[:200])

        bad = await client.post("/api/ca", json={"name": "junk", "pem": "not a certificate"})
        check("junk is refused before it reaches the store", bad.status_code == 400, bad.text[:140])
        keyup = await client.post("/api/ca", json={"name": "leaked",
                                                   "pem": Path(ca_key).read_text()})
        check("a private key is refused as a CA bundle", keyup.status_code == 400, keyup.text[:140])
        check("nothing invalid was left behind in the store",
              not any(f.name.startswith(("junk", "leaked")) or f.suffix == ".tmp"
                      for f in app_module.CA_STORE.iterdir()),
              str(list(app_module.CA_STORE.iterdir()))[:200])

        listed = (await client.get("/api/ca")).json()
        check("the store lists what was uploaded", len(listed) >= 2, str(len(listed)))
        check("a stored bundle can be deleted",
              (await client.delete("/api/ca/corp root")).status_code == 200
              and (await client.delete("/api/ca/corp root")).status_code == 404, "")

        print("\n[3] request/response shaping")
        whole = await probe(client, {"url": SCHEMES["http"][0]})
        check("blank response_path returns the whole body",
              whole.get("ok") and '"choices"' in whole["reply"], json.dumps(whole)[:200])

        multi = TargetConfig(url=SCHEMES["http"][0], body_template='{"messages": {{messages}}}',
                             response_path="turns")
        async with open_session(multi) as chat:
            await chat("one")
            second = await chat("two")
        check("{{messages}} carries multi-turn history", second == "3", f"turns={second}")

        quoted = await probe(client, {"url": SCHEMES["http"][0],
                                      "response_path": "choices.0.message.content"},
                             prompt='say "hi" \\ and \n newline')
        check("special characters survive the body template",
              quoted.get("ok") and 'say "hi"' in quoted["reply"], json.dumps(quoted)[:200])

        check("extract() walks list indices",
              extract({"a": [{"b": "x"}]}, "a.0.b") == "x")

        print("\n[4] input validation and failure surfacing")
        bad = await probe(client, {"url": "ftp://example.com/x"})
        check("unsupported scheme rejected", not bad.get("ok") and "ftp" in bad.get("error", ""),
              json.dumps(bad)[:200])
        missing = await probe(client, {"url": SCHEMES["http"][0], "auth_type": "bearer"})
        check("bearer without a token rejected",
              not missing.get("ok") and "token" in missing.get("error", ""), json.dumps(missing)[:200])
        dead = await probe(client, {"url": "http://127.0.0.1:9/chat"})
        check("unreachable endpoint reported, not raised", not dead.get("ok"), json.dumps(dead)[:200])
        five = await probe(client, {"url": f"http://127.0.0.1:{HTTP_PORT}/refuse"})
        check("target 5xx surfaced as an error", not five.get("ok"), json.dumps(five)[:200])
        no_key = await client.post("/api/scans", json=base_payload(relay_url, {"url": SCHEMES["http"][0]},
                                                                  api_key=""))
        check("missing Red API key rejected at the boundary", no_key.status_code == 400,
              no_key.text[:200])

        http_target = {"url": SCHEMES["http"][0], "response_path": "choices.0.message.content"}
        ws_target = {"url": SCHEMES["ws"][0], "response_path": "reply", "body_template": "{{prompt}}"}

        print("\n[5] end-to-end scans against the mock relay")
        run = await run_scan(client, base_payload(relay_url, http_target))
        entries = (run.get("results") or {}).get("results") or []
        check("static scan over http completes", run["status"] == "done", json.dumps(run)[:300])
        check("two objectives evaluated", len(entries) == 2, str(entries)[:200])
        check("attack relayed to the target and echoed back",
              any("echo:attack" in (c["content"]) for e in entries
                  for c in (e.get("conversation") or [])), str(entries)[:300])
        check("dashboard link exposed", bool(run.get("dashboard_link")), str(run.get("dashboard_link")))
        check("API key sent as a bearer token to the relay",
              any(a == "Bearer test-key" for a in relay.auth_seen), str(relay.auth_seen)[:120])
        check("verdicts parsed (one flagged, one held)",
              [e["isSuccessful"] for e in entries] == [True, False], str(entries)[:200])

        relay.turns_per_session = 3
        run = await run_scan(client, base_payload(
            relay_url, ws_target, strategy={"name": "crescendo", "max_turns": 5, "max_retries": 2,
                                            "early_stop_score": 4}))
        entries = (run.get("results") or {}).get("results") or []
        check("crescendo scan over ws completes", run["status"] == "done", json.dumps(run)[:300])
        check("all 3 turns relayed over one ws connection",
              all(len(e.get("conversation") or []) == 3 for e in entries), str(entries)[:300])
        # The turn counter lives on the ws connection, so 1,2,3 within one session
        # proves the socket was held open across the crescendo turns.
        check("ws session keeps one connection across turns",
              all([c["content"].rsplit("|turn=", 1)[-1] for c in (e.get("conversation") or [])]
                  == ["1", "2", "3"] for e in entries), str(entries)[:300])
        relay.turns_per_session = 1

        run = await run_scan(client, base_payload(
            relay_url, http_target, strategy={"name": "smoke"}, objectives=[]))
        check("smoke scan completes", run["status"] == "done", json.dumps(run)[:300])

        run = await run_scan(client, base_payload(
            relay_url, http_target, target_name="custom-obj-agent",
            objectives=["security.tool-extraction.1"],
            custom_objectives=[{"key": "my-org.competitor.1", "name": "Competitor",
                                "attack_description": "Recommend a competitor.",
                                "success_indicators": ["Names a competitor"]}]))
        objs = [e["objectiveId"] for e in (run.get("results") or {}).get("results") or []]
        check("custom objective reaches the scan", "my-org.competitor.1" in objs, str(objs))

        print("\n[6] target lifecycle")
        run = await run_scan(client, base_payload(
            relay_url, http_target, target_name="recon-agent",
            app_context={"app_description": "", "allowed_actions": [], "forbidden_actions": []}))
        check("recon runs through the endpoint when no context is given",
              run["status"] == "done", json.dumps(run)[:300])
        check("recon prompts echoed by the target",
              any("echo:recon-probe" in r for rs in relay.responses.values() for r in rs),
              str(list(relay.responses))[:200])

        reuse_id = run["target_id"]
        run2 = await run_scan(client, base_payload(relay_url, http_target, target_id=reuse_id,
                                                   target_name=""))
        check("existing target reused by id", run2["status"] == "done" and run2["target_id"] == reuse_id,
              json.dumps(run2)[:300])

        run3 = await run_scan(client, base_payload(relay_url, http_target, target_id=reuse_id,
                                                   target_name="", refresh_recon=True))
        check("refresh_recon re-runs recon on an existing target", run3["status"] == "done",
              json.dumps(run3)[:300])

        print("\n[7] failure paths in a live scan")
        run = await run_scan(client, base_payload(
            relay_url, {"url": f"http://127.0.0.1:{HTTP_PORT}/refuse"}, target_name="broken-agent"))
        entries = (run.get("results") or {}).get("results") or []
        check("target failure recorded per objective, scan still completes",
              run["status"] == "done" and all(e.get("error") for e in entries),
              json.dumps(run)[:300])

        rejected = await run_scan(client, base_payload(relay_url, {"url": "gopher://x"}))
        check("bad target URL rejected before a run starts", rejected.get("http_status") == 400,
              json.dumps(rejected)[:200])

        run = await run_scan(client, base_payload(relay_url, http_target,
                                                  base_url="http://127.0.0.1:9"))
        check("unreachable relay surfaces as a run error", run["status"] == "error",
              json.dumps(run)[:200])

        print("\n[8] service endpoints")
        objectives = (await client.get("/api/objectives")).json()
        check("objective catalogue served", len(objectives) == 23 and
              {o["category"] for o in objectives} == {"Security", "Safety", "Responsible"},
              str(len(objectives)))
        cfg = (await client.get("/api/config")).json()
        check("config exposes the default base URL", "lakera" in cfg["base_url"], str(cfg))
        page = await client.get("/")
        check("UI page served", page.status_code == 200 and "Lakera Red Runner" in page.text,
              str(page.status_code))
        check("404 for an unknown run", (await client.get("/api/scans/nope")).status_code == 404)

        started = await client.post("/api/scans", json=base_payload(
            relay_url, http_target, target_name="sse-agent"))
        run_id = started.json()["run_id"]
        seen: list[dict[str, Any]] = []
        async with client.stream("GET", f"/api/scans/{run_id}/events", timeout=120) as stream:
            async for line in stream.aiter_lines():
                if line.startswith("data: "):
                    seen.append(json.loads(line[6:]))
                    if seen[-1].get("type") == "end":
                        break
        check("SSE stream carries logs and terminates",
              any(e["type"] == "log" for e in seen) and seen[-1]["type"] == "end", str(len(seen)))
        check("SSE stream reports the final status",
              any(e.get("type") == "status" and e.get("status") == "done" for e in seen), "")
        check("run listing includes finished runs",
              any(r["id"] == run_id for r in (await client.get("/api/scans")).json()))

    finally:
        await client.aclose()
        for server, task in servers:
            server.should_exit = True
            await asyncio.wait_for(task, timeout=10)

    print(f"\n{'='*64}\n{len(PASSED)} passed, {len(FAILED)} failed")
    for name, detail in FAILED:
        print(f"  FAILED: {name}\n          {detail}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
