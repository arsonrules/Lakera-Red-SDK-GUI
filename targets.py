"""Adapter that turns a user-supplied endpoint (http/https/ws/wss) into an
async chat callable the Lakera Red session handler can drive.

TLS verification is opt-in (default off) so self-signed / corporate-MITM'd
endpoints work out of the box -- this is a red-teaming tool pointed at systems
the operator owns, not a general-purpose client.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import httpx
import websockets

from tls_doctor import read_ca_pems

AuthType = Literal["none", "bearer", "basic", "api_key"]

DEFAULT_HTTP_BODY = '{"message": "{{prompt}}"}'
DEFAULT_WS_BODY = "{{prompt}}"


@dataclass
class TargetConfig:
    url: str
    auth_type: AuthType = "none"
    token: str = ""           # bearer token / api key value
    username: str = ""        # basic
    password: str = ""        # basic
    api_key_header: str = "X-API-Key"
    method: str = "POST"      # http only
    body_template: str = ""   # {{prompt}} / {{messages}} placeholders
    response_path: str = ""   # dot path into the JSON reply, e.g. choices.0.message.content
    headers: dict[str, str] = field(default_factory=dict)
    verify_tls: bool = False
    ca_bundle: str = ""     # PEM file or directory of CAs to trust (implies verify_tls)
    timeout: float = 60.0

    @property
    def scheme(self) -> str:
        return urlparse(self.url).scheme.lower()

    def validate(self) -> None:
        if self.scheme not in ("http", "https", "ws", "wss"):
            raise ValueError(f"unsupported scheme {self.scheme!r}: use http, https, ws or wss")
        if self.auth_type not in ("none", "bearer", "basic", "api_key"):
            raise ValueError(f"unknown auth type {self.auth_type!r}")
        if self.auth_type == "bearer" and not self.token:
            raise ValueError("bearer auth requires a token")
        if self.auth_type == "basic" and not (self.username or self.password):
            raise ValueError("basic auth requires a username and/or password")
        if self.ca_bundle and not Path(self.ca_bundle).exists():
            raise ValueError(f"CA bundle not found: {self.ca_bundle}")
        if self.auth_type == "api_key":
            if not self.token:
                raise ValueError("api key auth requires a key value")
            if not self.api_key_header:
                raise ValueError("api key auth requires a header name")


def auth_headers(cfg: TargetConfig) -> dict[str, str]:
    """Auth headers for the configured method. Credentials never go in the URL."""
    if cfg.auth_type == "bearer":
        return {"Authorization": f"Bearer {cfg.token}"}
    if cfg.auth_type == "basic":
        raw = f"{cfg.username}:{cfg.password}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}
    if cfg.auth_type == "api_key":
        return {cfg.api_key_header: cfg.token}
    return {}


def _render(template: str, prompt: str, messages: list[dict[str, str]]) -> str:
    # json.dumps(...)[1:-1] escapes the prompt for interpolation inside a JSON string literal.
    return template.replace("{{prompt}}", json.dumps(prompt)[1:-1]).replace(
        "{{messages}}", json.dumps(messages)
    )


def extract(payload: Any, path: str) -> str:
    """Pull the reply text out of a response body via a dot path ('a.0.b')."""
    if not path:
        return payload if isinstance(payload, str) else json.dumps(payload)
    node = payload
    for part in path.split("."):
        if isinstance(node, list):
            node = node[int(part)]
        elif isinstance(node, dict):
            node = node[part]
        else:
            raise KeyError(f"cannot descend into {type(node).__name__} at {part!r} of {path!r}")
    return node if isinstance(node, str) else json.dumps(node)


class TlsTrustError(Exception):
    """A certificate that verification rejected, reported with the way out."""


def build_ssl_context(cfg: TargetConfig) -> ssl.SSLContext:
    """One trust store for both transports.

    httpx and websockets disagree by default -- httpx trusts certifi's roots
    while ssl.create_default_context() trusts OpenSSL's -- so the same endpoint
    could verify over https and fail over wss. Both paths go through here.
    """
    if not (cfg.verify_tls or cfg.ca_bundle):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    if cfg.ca_bundle:  # an explicit bundle replaces the default roots outright
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(cadata="".join(read_ca_pems(cfg.ca_bundle)[0]))
        return ctx

    if os.environ.get("SSL_CERT_FILE"):
        return ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
    if os.environ.get("SSL_CERT_DIR"):
        return ssl.create_default_context(capath=os.environ["SSL_CERT_DIR"])

    # Union of the OpenSSL system store and certifi's, so enabling verification
    # never fails purely because of which store a transport happens to prefer.
    ctx = ssl.create_default_context()
    try:
        import certifi

        ctx.load_verify_locations(cafile=certifi.where())
    except (ImportError, OSError):
        pass
    return ctx


def explain_tls_failure(exc: BaseException, cfg: TargetConfig) -> str | None:
    """Turn an OpenSSL verification error into something actionable, or None."""
    cause: BaseException | None = exc
    while cause and not isinstance(cause, ssl.SSLCertVerificationError):
        cause = cause.__cause__ or cause.__context__
    if not isinstance(cause, ssl.SSLCertVerificationError):
        return None
    reason = (cause.verify_message or str(cause)).lower()
    if "unable to get local issuer" in reason or "self-signed certificate in cert" in reason:
        detail = ("The endpoint's certificate chains to a CA this service does not trust, or the "
                  "server did not send its intermediate certificate. This is what a corporate "
                  "TLS-inspection proxy or an internal PKI looks like.")
        fix = ("Point 'CA bundle' at the issuing root CA in PEM form (export it from your proxy "
               "vendor or run the TLS diagnosis to see which issuer is being presented).")
    elif "self-signed certificate" in reason:
        detail = "The endpoint presents a self-signed certificate, so there is no CA to chain to."
        fix = "Point 'CA bundle' at that certificate itself, or untick 'Verify TLS certificate'."
    elif "hostname mismatch" in reason or "match" in reason:
        detail = f"The certificate is not valid for the host in {cfg.url}."
        fix = "Use the hostname the certificate was issued for, or untick verification."
    elif "expired" in reason:
        detail = "The endpoint's certificate has expired."
        fix = "Renew the certificate on the endpoint."
    else:
        detail = f"Certificate verification failed: {cause.verify_message or cause}"
        fix = "Run the TLS diagnosis for the presented chain."
    return f"{detail} {fix}"


@asynccontextmanager
async def open_session(cfg: TargetConfig):
    """Yield an async `chat(prompt) -> reply` bound to one conversation.

    Multi-turn history is kept per session so crescendo scans escalate against a
    target that actually sees the prior turns: HTTP targets get it via the
    {{messages}} placeholder, WS targets via a connection held open for the session.
    """
    cfg.validate()
    history: list[dict[str, str]] = []
    headers = {**auth_headers(cfg), **cfg.headers}

    if cfg.scheme in ("http", "https"):
        template = cfg.body_template or DEFAULT_HTTP_BODY
        async with httpx.AsyncClient(verify=build_ssl_context(cfg), timeout=cfg.timeout) as client:

            async def chat(prompt: str) -> str:
                history.append({"role": "user", "content": prompt})
                body = _render(template, prompt, history)
                res = await client.request(
                    cfg.method.upper(),
                    cfg.url,
                    content=body.encode(),
                    headers={"Content-Type": "application/json", **headers},
                )
                res.raise_for_status()
                try:
                    payload: Any = res.json()
                except ValueError:
                    payload = res.text
                reply = extract(payload, cfg.response_path)
                history.append({"role": "assistant", "content": reply})
                return reply

            yield chat
        return

    template = cfg.body_template or DEFAULT_WS_BODY
    async with websockets.connect(
        cfg.url,
        additional_headers=headers or None,
        ssl=build_ssl_context(cfg) if cfg.scheme == "wss" else None,
        open_timeout=cfg.timeout,
        close_timeout=cfg.timeout,
        max_size=None,
    ) as ws:

        async def chat(prompt: str) -> str:
            history.append({"role": "user", "content": prompt})
            await ws.send(_render(template, prompt, history))
            raw = await ws.recv()
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", "replace")
            try:
                payload: Any = json.loads(raw)
            except ValueError:
                payload = raw
            reply = extract(payload, cfg.response_path)
            history.append({"role": "assistant", "content": reply})
            return reply

        yield chat
