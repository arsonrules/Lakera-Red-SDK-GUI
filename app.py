"""Interactive web service for triggering Lakera Red SDK scans.

Point it at any http/https/ws/wss chat endpoint (optionally one that streams its
reply over SSE), pick an auth method, choose objectives and a strategy, and watch
the scan stream live.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import os
import re
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from lakera_red_sdk import (
    CrescendoStrategyOptions,
    CustomObjective,
    GroundTruth,
    LakeraRedClient,
    ReconContext,
    SmokeStrategyOptions,
    StaticStrategyOptions,
)
from pydantic import BaseModel, Field

from targets import TargetConfig, explain_tls_failure, open_session
from tls_doctor import MAX_CA_BYTES, adiagnose, read_ca_pems

HERE = Path(__file__).parent
# Uploaded CA bundles live here. Override for a container with a mounted volume.
CA_STORE = Path(os.environ.get("LAKERA_RED_CA_STORE", HERE / "ca_store"))
DEFAULT_BASE_URL = os.environ.get("LAKERA_RED_BASE_URL", "https://red-webhooks.lakera.ai")

OBJECTIVES = [
    ("security.instruction-override.1", "Instruction Override", "Security"),
    ("security.system-prompt-extraction.1", "System Prompt Extraction", "Security"),
    ("security.tool-extraction.1", "Tool Extraction", "Security"),
    ("security.data-exfiltration.1", "Data Exfiltration / PII Leakage", "Security"),
    ("safety.hate-speech.1", "Hate Speech", "Safety"),
    ("safety.violence-extremism.1", "Violence and Violent Extremism", "Safety"),
    ("safety.cbrne.1", "CBRNE", "Safety"),
    ("safety.self-harm.1", "Self-Harm", "Safety"),
    ("safety.sexual-content.1", "Sexual Content", "Safety"),
    ("safety.harassment-bullying.1", "Harassment and Bullying", "Safety"),
    ("safety.dangerous-instructions.1", "Dangerous Instructions", "Safety"),
    ("safety.drug-synthesis.1", "Drug Synthesis", "Safety"),
    ("responsible.misinformation.1", "Misinformation and Disinformation", "Responsible"),
    ("responsible.copyright-infringement.1", "Copyright Infringement", "Responsible"),
    ("responsible.fraud-facilitation.1", "Fraud Facilitation", "Responsible"),
    ("responsible.criminal-advice.1", "Criminal Advice", "Responsible"),
    ("responsible.brand-damaging.1", "Brand-Damaging Content", "Responsible"),
    ("responsible.unauthorized-discounts.1", "Unauthorized Discounts", "Responsible"),
    ("responsible.discrimination-bias.1", "Discrimination and Bias", "Responsible"),
    ("responsible.specialized-advice.1", "Specialized Advice (Medical, Legal)", "Responsible"),
    ("responsible.defamation-libel.1", "Defamation and Libel", "Responsible"),
    ("responsible.hallucination.1", "Hallucination", "Responsible"),
    ("responsible.cybercrime-facilitation.1", "Cybercrime Facilitation", "Responsible"),
]


# --------------------------------------------------------------------------- models


class TargetSpec(BaseModel):
    url: str
    auth_type: Literal["none", "bearer", "basic", "api_key"] = "none"
    token: str = ""
    username: str = ""
    password: str = ""
    api_key_header: str = "X-API-Key"
    method: str = "POST"
    body_template: str = ""
    response_path: str = ""
    stream_url: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    verify_tls: bool = False
    ca_bundle: str = ""
    timeout: float = 60.0

    def to_config(self) -> TargetConfig:
        return TargetConfig(**self.model_dump())


class AppContextSpec(BaseModel):
    app_description: str = ""
    allowed_actions: list[str] = Field(default_factory=list)
    forbidden_actions: list[str] = Field(default_factory=list)

    def to_recon(self) -> ReconContext | None:
        if not (self.app_description or self.allowed_actions or self.forbidden_actions):
            return None
        return ReconContext(
            app_description=self.app_description,
            allowed_actions=self.allowed_actions,
            forbidden_actions=self.forbidden_actions,
        )


class GroundTruthSpec(BaseModel):
    system_prompt: str = ""
    tools: list[str] = Field(default_factory=list)

    def to_ground_truth(self) -> GroundTruth | None:
        if not (self.system_prompt or self.tools):
            return None
        return GroundTruth(
            system_prompt=self.system_prompt or None,
            tools="\n".join(self.tools) or None,
        )


class StrategySpec(BaseModel):
    name: Literal["static", "crescendo", "smoke"] = "static"
    number_of_probes: int | None = None
    max_turns: int | None = None
    max_retries: int | None = None
    early_stop_score: int | None = None
    probes: list[str] | None = None

    def to_options(self):
        if self.name == "static":
            return StaticStrategyOptions(number_of_probes=self.number_of_probes)
        if self.name == "crescendo":
            return CrescendoStrategyOptions(
                max_turns=self.max_turns,
                max_retries=self.max_retries,
                early_stop_score=self.early_stop_score,
            )
        return SmokeStrategyOptions(probes=self.probes or None)


class CustomObjectiveSpec(BaseModel):
    key: str
    name: str
    attack_description: str
    success_indicators: list[str]


class ScanRequest(BaseModel):
    # Lakera side
    api_key: str = ""
    base_url: str = DEFAULT_BASE_URL
    scan_name: str = "web-service scan"
    target_name: str = ""
    target_id: str = ""            # set to reuse an existing target by id
    refresh_recon: bool = False    # re-run recon on the target before scanning
    app_context: AppContextSpec = Field(default_factory=AppContextSpec)
    ground_truth: GroundTruthSpec = Field(default_factory=GroundTruthSpec)
    strategy: StrategySpec = Field(default_factory=StrategySpec)
    objectives: list[str] = Field(default_factory=list)
    custom_objectives: list[CustomObjectiveSpec] = Field(default_factory=list)
    concurrency: int = 3
    language: str = "en"
    # Target under test
    target: TargetSpec

    def resolved_key(self) -> str:
        # Trimmed: a pasted newline would make httpx quote the whole key in its error.
        key = (self.api_key or os.environ.get("LAKERA_RED_API_KEY", "")).strip()
        if not key:
            raise HTTPException(400, "No Red API key: pass api_key or set LAKERA_RED_API_KEY")
        return key


class CaPathRequest(BaseModel):
    path: str


class CaUploadRequest(BaseModel):
    name: str = ""
    pem: str = ""        # PEM text, pasted or read from a file
    data_b64: str = ""   # or the raw file bytes, base64 — covers binary DER


def _ca_slug(name: str) -> str:
    """A safe on-disk name: basename only, conservative characters, .pem suffix."""
    stem = Path(name or "uploaded").name
    stem = "".join(c if (c.isalnum() or c in "._-") else "-" for c in stem).strip(".-")
    stem = re.sub(r"\.(pem|crt|cer|der|cert)$", "", stem, flags=re.I) or "uploaded"
    return f"{stem[:64]}.pem"


def _describe(path: Path) -> dict[str, Any]:
    pems, names = read_ca_pems(path)
    return {"path": str(path), "name": path.name, "count": len(pems), "subjects": names}


class ProbeRequest(BaseModel):
    target: TargetSpec
    prompt: str = "Hello! Reply with a short greeting."


# --------------------------------------------------------------------------- run state


def _jsonable(value: Any) -> Any:
    """SDK log fields can hold exceptions and other non-JSON values; keep them printable."""
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


@dataclass
class Run:
    id: str
    status: str = "starting"
    logs: list[dict[str, Any]] = field(default_factory=list)
    scan_id: str | None = None
    target_id: str | None = None
    dashboard_link: str | None = None
    results: dict[str, Any] | None = None
    error: str | None = None
    started: float = field(default_factory=time.time)
    bell: asyncio.Event = field(default_factory=asyncio.Event)
    task: asyncio.Task | None = None

    def log(self, level: str, message: str, **fields: Any) -> None:
        self.logs.append(
            {
                "t": time.time(),
                "level": level,
                "message": str(message),
                "fields": _jsonable(fields) or None,
            }
        )
        self.bell.set()

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "scan_id": self.scan_id,
            "target_id": self.target_id,
            "dashboard_link": self.dashboard_link,
            "results": self.results,
            "error": self.error,
            "started": self.started,
            "log_count": len(self.logs),
        }


RUNS: dict[str, Run] = {}


class RunLogger:
    """Adapter so the SDK's structured logs land in the run's live stream."""

    def __init__(self, run: Run) -> None:
        self._run = run

    def debug(self, message: str, fields: dict[str, Any] | None = None) -> None:
        self._run.log("debug", message, **(fields or {}))

    def info(self, message: str, fields: dict[str, Any] | None = None) -> None:
        self._run.log("info", message, **(fields or {}))

    def warn(self, message: str, fields: dict[str, Any] | None = None) -> None:
        self._run.log("warn", message, **(fields or {}))

    def error(self, message: str, fields: dict[str, Any] | None = None) -> None:
        self._run.log("error", message, **(fields or {}))


# --------------------------------------------------------------------------- scan driver


def _make_handler(run: Run, cfg: TargetConfig):
    async def handler(session) -> None:
        run.log("info", "session opened", session_id=session.id)
        try:
            async with open_session(cfg) as chat:
                async for msg in session:
                    run.log("attack", msg.attack, session_id=session.id)
                    # ponytail: one log entry per SSE chunk so the UI shows the reply as it
                    # streams; coalesce them if replies grow long enough to bloat the log.
                    reply = await chat(msg.attack, on_chunk=lambda text: run.log(
                        "chunk", text, session_id=session.id))
                    run.log("reply", reply, session_id=session.id)
                    await msg.respond(reply)
        except Exception as exc:
            # Re-raise with the diagnosis attached so it reaches the objective's
            # error text, not just an opaque OpenSSL string.
            if hint := explain_tls_failure(exc, cfg):
                run.log("error", hint, session_id=session.id)
                raise RuntimeError(f"{exc} — {hint}") from exc
            raise
        run.log("info", "session closed", session_id=session.id)

    return handler


async def _execute(run: Run, req: ScanRequest, api_key: str) -> None:
    cfg = req.target.to_config()
    cfg.validate()
    handler = _make_handler(run, cfg)
    client = LakeraRedClient(
        api_key,
        base_url=req.base_url,
        log_level="info",
        logger=RunLogger(run),
    )
    try:
        run.status = "resolving target"
        if req.target_id:
            target = await client.get_target(req.target_id)
            run.log("info", "reusing target", target_id=target.target_id, name=target.name)
        else:
            target = await client.create_or_get_target(
                req.target_name or "web-service target",
                app_context=req.app_context.to_recon(),
                ground_truth=req.ground_truth.to_ground_truth(),
                handler=handler,
            )
            run.log("info", "target ready", target_id=target.target_id, name=target.name)
        run.target_id = target.target_id

        if req.refresh_recon:
            run.status = "recon"
            recon = await client.run_recon(target.target_id, handler)
            run.log("info", "recon finished", discovered=bool(recon))

        run.status = "creating scan"
        scan = await client.create_scan(
            target.target_id,
            name=req.scan_name,
            objectives=req.objectives or None,
            custom_objectives=[CustomObjective(**o.model_dump()) for o in req.custom_objectives]
            or None,
            strategy=req.strategy.to_options(),
            concurrency=req.concurrency,
            language=req.language or None,
        )
        run.scan_id = scan.scan_id
        run.dashboard_link = scan.dashboard_link
        run.log("info", "scan created", scan_id=scan.scan_id, dashboard=scan.dashboard_link)
        run.bell.set()

        run.status = "running"
        await scan.run(handler)

        run.status = "evaluating"
        results = await scan.get_results()
        for _ in range(30):
            if results.ready:
                break
            await asyncio.sleep(10)
            results = await scan.get_results()
        run.results = results.to_json()
        run.status = "done" if results.ready else "timed out waiting for evaluation"
        run.log("info", "results ready" if results.ready else "results not ready")
    except Exception as exc:  # surfaced to the UI rather than lost in a task
        run.status = "error"
        run.error = f"{type(exc).__name__}: {exc}"
        run.log("error", run.error)
        if hint := explain_tls_failure(exc, cfg):
            run.error = f"{run.error} — {hint}"
            run.log("error", hint)
    finally:
        await client.close()
        run.bell.set()


# --------------------------------------------------------------------------- api

app = FastAPI(title="Lakera Red Runner")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(HERE / "static" / "index.html")


@app.get("/api/objectives")
async def objectives() -> list[dict[str, str]]:
    return [{"id": i, "name": n, "category": c} for i, n, c in OBJECTIVES]


@app.get("/api/config")
async def config() -> dict[str, Any]:
    return {
        "base_url": DEFAULT_BASE_URL,
        "has_env_key": bool(os.environ.get("LAKERA_RED_API_KEY")),
    }


@app.post("/api/probe")
async def probe(req: ProbeRequest) -> dict[str, Any]:
    """Send one message to the target so the operator can verify connectivity/auth --
    for an SSE target, the StreamToken hand-off and the stream too."""
    cfg = req.target.to_config()
    chunks: list[str] = []
    trace: list[str] = []  # filled in place, so a failure still reports how far it got
    started = time.monotonic()
    try:
        cfg.validate()
        async with open_session(cfg) as chat:
            reply = await chat(req.prompt, on_chunk=chunks.append, trace=trace)
    except Exception as exc:
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "tls_hint": explain_tls_failure(exc, cfg),
            "trace": trace,
            "ms": int((time.monotonic() - started) * 1000),
        }
    return {"ok": True, "reply": reply, "ms": int((time.monotonic() - started) * 1000),
            "trace": trace, "chunks": len(chunks) or None}


@app.post("/api/ca")
async def upload_ca(req: CaUploadRequest) -> dict[str, Any]:
    """Store a CA bundle uploaded as file bytes (base64) or pasted as PEM text."""
    if req.data_b64:
        try:
            blob = base64.b64decode(req.data_b64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise HTTPException(400, f"data_b64 is not valid base64: {exc}") from exc
        label = req.name or "uploaded"
    elif req.pem.strip():
        blob, label = req.pem.encode(), (req.name or "pasted")
    else:
        raise HTTPException(400, "Provide a certificate file or PEM text")
    if len(blob) > MAX_CA_BYTES:
        raise HTTPException(400, f"Certificate exceeds {MAX_CA_BYTES // 1024} KB")

    CA_STORE.mkdir(parents=True, exist_ok=True)
    target = CA_STORE / _ca_slug(label)
    # Validate before it lands on disk, so the store only ever holds usable bundles.
    scratch = target.with_suffix(".tmp")
    scratch.write_bytes(blob)
    try:
        pems, subjects = read_ca_pems(scratch)
    except ValueError as exc:
        scratch.unlink(missing_ok=True)
        raise HTTPException(400, str(exc)) from exc
    scratch.replace(target)
    target.write_text("".join(pems))  # normalised to PEM, DER input included
    return {"path": str(target), "name": target.name, "count": len(pems), "subjects": subjects}


@app.get("/api/ca")
async def list_ca() -> list[dict[str, Any]]:
    if not CA_STORE.exists():
        return []
    out = []
    for f in sorted(CA_STORE.glob("*.pem")):
        try:
            out.append(_describe(f))
        except ValueError:
            continue
    return out


@app.delete("/api/ca/{name}")
async def delete_ca(name: str) -> dict[str, bool]:
    target = CA_STORE / _ca_slug(name)
    if not target.exists():
        raise HTTPException(404, "no such CA bundle")
    target.unlink()
    return {"deleted": True}


@app.post("/api/ca/inspect")
async def inspect_ca(req: CaPathRequest) -> dict[str, Any]:
    """Report what a server-side path holds — a file or a directory of certificates."""
    try:
        info = _describe(Path(req.path))
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, **info}


@app.post("/api/tls-check")
async def tls_check(req: ProbeRequest) -> dict[str, Any]:
    """Explain why an https/wss endpoint fails certificate verification."""
    cfg = req.target.to_config()
    try:
        return await adiagnose(cfg.url, ca_bundle=cfg.ca_bundle, timeout=min(cfg.timeout, 15.0))
    except ValueError as exc:
        return {"verdict": "not-tls", "findings": [str(exc)], "fixes": [], "stores": []}


@app.post("/api/scans")
async def start_scan(req: ScanRequest) -> dict[str, str]:
    api_key = req.resolved_key()
    try:
        req.target.to_config().validate()
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    run = Run(id=uuid.uuid4().hex[:12])
    RUNS[run.id] = run
    run.log("info", "run queued")
    run.task = asyncio.create_task(_execute(run, req, api_key))
    return {"run_id": run.id}


@app.get("/api/scans")
async def list_scans() -> list[dict[str, Any]]:
    return [r.snapshot() for r in sorted(RUNS.values(), key=lambda r: r.started, reverse=True)]


@app.get("/api/scans/{run_id}")
async def get_scan(run_id: str) -> dict[str, Any]:
    run = RUNS.get(run_id)
    if not run:
        raise HTTPException(404, "no such run")
    return {**run.snapshot(), "logs": run.logs}


@app.post("/api/scans/{run_id}/cancel")
async def cancel_scan(run_id: str) -> dict[str, Any]:
    run = RUNS.get(run_id)
    if not run:
        raise HTTPException(404, "no such run")
    if run.task and not run.task.done():
        run.task.cancel()
        run.status = "cancelled"
        run.log("warn", "run cancelled by operator")
        run.bell.set()
    return run.snapshot()


@app.get("/api/scans/{run_id}/events")
async def events(run_id: str) -> StreamingResponse:
    run = RUNS.get(run_id)
    if not run:
        raise HTTPException(404, "no such run")

    async def stream():
        sent = 0
        while True:
            while sent < len(run.logs):
                yield f"data: {json.dumps({'type': 'log', **run.logs[sent]})}\n\n"
                sent += 1
            yield f"data: {json.dumps({'type': 'status', **run.snapshot()})}\n\n"
            if run.status in ("done", "error", "cancelled") or run.status.startswith("timed out"):
                yield "data: {\"type\": \"end\"}\n\n"
                return
            run.bell.clear()
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(run.bell.wait(), timeout=15)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
