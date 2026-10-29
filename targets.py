"""Adapter that turns a user-supplied endpoint (http/https/ws/wss) into an
async chat callable the Lakera Red session handler can drive.

An http(s) target may also stream its answer: it replies with
message.StreamToken, and the text arrives from a separate SSE endpoint opened
with that token as the last segment of its URL: /path/to/{StreamToken}.

TLS verification is opt-in (default off) so self-signed / corporate-MITM'd
endpoints work out of the box -- this is a red-teaming tool pointed at systems
the operator owns, not a general-purpose client.
"""

from __future__ import annotations

import base64
import codecs
import json
import os
import re
import ssl
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote, urljoin, urlparse, urlunparse

import httpx
import websockets

from tls_doctor import read_ca_pems

AuthType = Literal["none", "bearer", "basic", "api_key"]

DEFAULT_HTTP_BODY = '{"message": "{{prompt}}"}'
DEFAULT_WS_BODY = "{{prompt}}"
DEFAULT_STREAM_PATH = "content"  # the field each SSE event carries its text chunk in
# Key names looked for anywhere in the target's reply, matched ignoring case and separators.
TOKEN_KEY = "streamtoken"
URL_KEYS = ("streamurl", "streamuri", "streamendpoint", "sseurl")
# A {StreamToken} placeholder in the SSE URL marks where the token goes; without one it ends the path.
# Braces may arrive percent-encoded when the URL was copied out of a browser.
TOKEN_SLOT = re.compile(r"(?:\{|%7B){1,2}StreamToken(?:\}|%7D){1,2}", re.I)

# What HTTP will carry as a header value: printable ASCII, inner spaces allowed, none at the ends.
HEADER_VALUE = re.compile(r"(?:[!-~](?:[ \t!-~]*[!-~])?)?")
_EOL = re.compile(r"\r\n|\r|\n")


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
    stream_url: str = ""      # SSE endpoint; set = the reply streams via message.StreamToken
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
        # _render fills in only these two, so any other {{...}} would reach the target verbatim.
        for name in re.findall(r"\{\{([^{}]*)\}\}", self.body_template):
            if name not in ("prompt", "messages"):
                raise ValueError(f"unknown placeholder {{{{{name}}}}} in the request body — only "
                                 "{{prompt}} and {{messages}} are filled in; write any other value "
                                 "literally")
        # A dot path never holds "://"; a URL here gets split on its dots and surfaces as an
        # opaque KeyError: 'https://apiai' from the first segment.
        if "://" in self.response_path:
            raise ValueError("Response path looks like a URL — it is a dot path into the reply "
                             "(e.g. choices.0.message.content); put the stream endpoint in "
                             "'SSE stream URL' instead")
        if self.auth_type == "api_key":
            if not self.token:
                raise ValueError("api key auth requires a key value")
            if not self.api_key_header:
                raise ValueError("api key auth requires a header name")
        # A ws/wss target that streams needs the SSE URL here, since its reply only
        # carries the token, not where to spend it; http targets can fall back to
        # their own URL, so the field stays optional for them.
        if self.stream_url and urlparse(self.stream_url).scheme.lower() not in ("http", "https"):
            raise ValueError("SSE stream URL must be http or https")
        # h11 quotes a rejected header value verbatim in its error, which would carry a
        # secret into the UI, the run log and the error Red is sent -- so refuse by name.
        for name, value in {**auth_headers(self), **self.headers}.items():
            if not HEADER_VALUE.fullmatch(value):
                raise ValueError(f"header {name!r} has a stray space, line break or non-ASCII "
                                 "character — check the pasted value")


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


def _walk(payload: Any, path: str) -> Any:
    node = payload
    for part in path.split("."):
        if isinstance(node, list):
            node = node[int(part)]
        elif isinstance(node, dict):
            node = node[part]
        else:
            raise KeyError(f"cannot descend into {type(node).__name__} at {part!r} of {path!r}")
    return node


def extract(payload: Any, path: str) -> str:
    """Pull the reply text out of a response body via a dot path ('a.0.b')."""
    node = _walk(payload, path) if path else payload
    return node if isinstance(node, str) else json.dumps(node)


def _keyish(name: str) -> str:
    """Compare key names ignoring case and separators, so Stream_Token == streamToken."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _walk_json(node: Any, path: str = "") -> Iterator[tuple[str, str, Any]]:
    """Every (path, key, value) in a reply, descending into objects nested as JSON strings."""
    if isinstance(node, str) and node.lstrip()[:1] in ("{", "["):
        try:
            node = json.loads(node)
        except ValueError:
            return
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else key
            yield here, key, value
            yield from _walk_json(value, here)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk_json(value, f"{path}.{index}" if path else str(index))


def find_token(payload: Any) -> tuple[str | None, str]:
    """The StreamToken and where it was found.

    message.StreamToken wins; otherwise the shallowest StreamToken anywhere in the
    reply, because targets put it at the top level, under a data envelope, or inside
    a JSON string -- and a token that is never found is a stream that never opens.
    """
    best: tuple[int, str, str] | None = None
    for path, key, value in _walk_json(payload):
        if _keyish(key) == TOKEN_KEY and isinstance(value, str) and value.strip():
            if path == "message.StreamToken":
                return value.strip(), path
            depth = path.count(".")
            if best is None or depth < best[0]:
                best = (depth, value.strip(), path)
    return (best[1], best[2]) if best else (None, "")


def _http_base(url: str) -> str:
    """The target as an http(s) origin, so a wss target's relative stream path
    resolves to https, not an unusable wss URL."""
    p = urlparse(url)
    scheme = {"wss": "https", "ws": "http"}.get(p.scheme.lower(), p.scheme.lower())
    return urlunparse((scheme, p.netloc, p.path, "", "", ""))


def find_stream_url(payload: Any, cfg: TargetConfig) -> tuple[str, str]:
    """Where to open the SSE stream, and how that was decided.

    A configured stream_url wins, then a stream URL the reply names itself (a
    relative path resolves against the target). An http target then falls back to
    its own URL; a ws target cannot -- SSE is not WebSocket -- so it says so.
    """
    if cfg.stream_url:
        return cfg.stream_url, "configured SSE stream URL"
    for path, key, value in _walk_json(payload):
        if (_keyish(key) in URL_KEYS and isinstance(value, str)
                and value.startswith(("http://", "https://", "/"))):
            return urljoin(_http_base(cfg.url), value), f"{path} returned by the target"
    if cfg.scheme in ("http", "https"):
        return cfg.url, "the target URL itself, none configured or returned"
    raise ValueError("the target returned a StreamToken but no stream URL, and a ws/wss "
                     "target cannot be the SSE endpoint — set the SSE stream URL to the "
                     "https endpoint the token opens")


def token_url(url: str, token: str) -> str:
    """The SSE URL with the token as its last path segment -- /path/to/{StreamToken} --
    or in place of a {StreamToken} placeholder. The query string is kept."""
    if TOKEN_SLOT.search(url):
        return TOKEN_SLOT.sub(lambda _: token, url)
    p = urlparse(url)
    return urlunparse(p._replace(path=f"{p.path.rstrip('/')}/{token}"))


def find_content(event: Any, path: str) -> tuple[str | None, str]:
    """The text in one SSE event: the configured path first, then any content key.

    The fallback catches events shaped like choices.0.delta.content without needing
    the path spelled out.
    """
    try:
        node = _walk(event, path)
        if isinstance(node, str):
            return node, path
    except (ValueError, KeyError, IndexError, TypeError):
        pass
    for where, key, value in _walk_json(event):
        if _keyish(key) == "content" and isinstance(value, str):
            return value, where
    return None, ""


def _note(trace: list[str] | None, step: str) -> None:
    """Record a step of the hand-off, so a failed connection test says how far it got."""
    if trace is not None:
        trace.append(step)


def _no_token(payload: Any) -> ValueError:
    """Say what the reply held instead -- key paths only, never values."""
    paths = [path for path, _, _ in _walk_json(payload)]
    held = f"keys: {paths[:40]}" if paths else "the reply is not a JSON object"
    return ValueError(f"target reply has no StreamToken ({held})")


async def _lines(res: httpx.Response) -> AsyncIterator[str]:
    """Lines as they arrive, split at CRLF, LF or CR only, as SSE specifies.

    httpx's aiter_lines() uses str.splitlines(), which also breaks on U+2028 and
    U+0085 -- characters a JSON payload may carry raw.
    """
    decoder = codecs.getincrementaldecoder("utf-8-sig")("replace")  # SSE is UTF-8, BOM dropped
    buf = ""
    async for chunk in res.aiter_bytes():
        buf += decoder.decode(chunk)
        held = buf.endswith("\r")  # may be the first half of a CRLF split across reads
        *lines, buf = _EOL.split(buf[:-1] if held else buf)
        buf += "\r" if held else ""
        for line in lines:
            yield line
    for line in _EOL.split(buf + decoder.decode(b"", final=True)):
        yield line


async def _sse_data(res: httpx.Response) -> AsyncIterator[str]:
    """The data of each SSE event; comments and event/id/retry fields are ignored."""
    data: list[str] = []
    async for line in _lines(res):
        if line:
            name, _, value = line.partition(":")
            if name == "data":
                data.append(value.removeprefix(" "))
        elif data:
            yield "\n".join(data)
            data = []
    if data:  # a stream that closes without the final blank line still delivers
        yield "\n".join(data)


def _json_docs(data: str) -> Iterator[Any]:
    """Every top-level JSON value in one SSE event's data.

    Usually one, but some targets concatenate several -- a `text` object and a
    `done` object on separate data lines of the same event, say -- which json.loads
    rejects as a whole. raw_decode reads them one after another instead, and a single
    object split across data lines (its newline now inside the JSON) still parses as one.
    """
    decoder = json.JSONDecoder()
    index, length = 0, len(data)
    while index < length:
        while index < length and data[index] in " \t\r\n":
            index += 1
        if index >= length:
            return
        try:
            value, index = decoder.raw_decode(data, index)
        except ValueError:
            return  # a heartbeat, a half-written event, or trailing noise
        yield value


async def _stream_reply(cfg: TargetConfig, payload: Any,
                        on_chunk: Callable[[str], object] | None,
                        trace: list[str] | None = None, body: str = "") -> str:
    """Open the SSE stream at /path/to/{StreamToken} and join each event's content as
    it arrives. Errors say what went wrong, never the token or a body.

    Its own client, on the same TLS trust and auth as the target: the SSE endpoint is a
    separate connection (and, for a ws target, a different transport entirely)."""
    token, where = find_token(payload)
    if not token:
        raise _no_token(payload)
    base, why = find_stream_url(payload, cfg)
    # The token is a credential in the URL, so only `shown` goes in a trace or an error.
    url, shown = token_url(base, quote(token, safe="")), token_url(base, "{StreamToken}")
    _note(trace, f"StreamToken found at {where}; opening SSE at {shown} ({why})")
    headers = httpx.Headers({**auth_headers(cfg), **cfg.headers})
    headers["Accept"] = "text/event-stream"
    path = cfg.response_path or DEFAULT_STREAM_PATH
    parts: list[str] = []
    events = skipped = 0
    found_at = ""
    async with httpx.AsyncClient(verify=build_ssl_context(cfg), timeout=cfg.timeout) as client:
        try:
            res = await client.send(client.build_request("GET", url, headers=headers), stream=True)
        except httpx.TransportError as exc:
            # A TLS target whose stream URL is plaintext http hangs then resets (an opaque,
            # empty-message ReadError). The host answers the WebSocket over TLS, so the stream
            # is almost surely https -- upgrade the scheme and retry once, rather than fail.
            if not (cfg.scheme in ("https", "wss") and urlparse(base).scheme.lower() == "http"):
                raise
            base = urlunparse(urlparse(base)._replace(scheme="https"))
            url, shown = token_url(base, quote(token, safe="")), token_url(base, "{StreamToken}")
            _note(trace, f"plaintext http stream failed ({type(exc).__name__}); "
                         f"retrying over https at {shown}")
            try:
                res = await client.send(client.build_request("GET", url, headers=headers), stream=True)
            except httpx.TransportError as exc2:
                raise ValueError(f"could not open the SSE stream at {shown} over https either "
                                 f"({type(exc2).__name__}); check the stream URL and CA bundle") from exc2
        if res.status_code == 405:  # some gateways stream only from a POST
            await res.aclose()
            _note(trace, "SSE endpoint refused GET (405), retrying as POST")
            headers["Content-Type"] = "application/json"
            res = await client.send(
                client.build_request("POST", url, headers=headers, content=body.encode()),
                stream=True)
        try:
            _note(trace, f"SSE endpoint answered {res.status_code} "
                         f"{res.headers.get('content-type') or 'with no content-type'}")
            if res.is_error:  # not raise_for_status(): its message quotes the URL, token and all
                raise ValueError(f"the SSE endpoint {shown} answered HTTP {res.status_code}")
            async for data in _sse_data(res):
                if data.strip() == "[DONE]":
                    break
                events += 1
                carried = False
                for event in _json_docs(data):  # usually one, but a target may pack several
                    piece, at = find_content(event, path)
                    if piece is None:  # metadata, or the null content some streams sign off with
                        continue
                    carried = True
                    found_at = found_at or at
                    parts.append(piece)
                    if piece and on_chunk:
                        on_chunk(piece)
                if not carried:  # a heartbeat, a half-written event, or content-free metadata
                    skipped += 1
        finally:
            await res.aclose()
    _note(trace, f"{events} event(s): {len(parts)} carried text"
                 + (f" at {found_at!r}" if found_at else "") + f", {skipped} skipped")
    if not parts:
        raise ValueError(f"the SSE stream at {shown} sent {events} event(s) but none carried "
                         f"{path!r} text (content-type: {res.headers.get('content-type')})")
    return "".join(parts)


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

    if cfg.ca_bundle:  # add the bundle to the default roots, not in place of them, so a
        ctx = ssl.create_default_context()  # server that merely omits its intermediate (the
        ctx.load_verify_locations(cadata="".join(read_ca_pems(cfg.ca_bundle)[0]))  # bundle) still
        return ctx  # chains to a public root, as does an internal CA supplied on its own

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
    """Yield an async `chat(prompt, on_chunk=None) -> reply` bound to one conversation.

    Multi-turn history is kept per session so crescendo scans escalate against a
    target that actually sees the prior turns: HTTP targets get it via the
    {{messages}} placeholder, WS targets via a connection held open for the session.
    A reply carrying a StreamToken anywhere in it is always read from SSE, whether it
    came over http or over the WebSocket; configuring a stream_url overrides where that
    stream lives (and is required for a ws target, whose reply names only the token).
    on_chunk sees each piece of text as it lands, the joined text is what chat returns,
    and trace collects the hand-off steps for the connection test.
    """
    cfg.validate()
    history: list[dict[str, str]] = []
    headers = {**auth_headers(cfg), **cfg.headers}

    if cfg.scheme in ("http", "https"):
        template = cfg.body_template or DEFAULT_HTTP_BODY
        async with httpx.AsyncClient(verify=build_ssl_context(cfg), timeout=cfg.timeout) as client:

            async def chat(prompt: str, on_chunk: Callable[[str], object] | None = None,
                           trace: list[str] | None = None) -> str:
                history.append({"role": "user", "content": prompt})
                body = _render(template, prompt, history)
                res = await client.request(
                    cfg.method.upper(),
                    cfg.url,
                    content=body.encode(),
                    headers={"Content-Type": "application/json", **headers},
                )
                _note(trace, f"{cfg.method.upper()} {cfg.url} → HTTP {res.status_code}")
                res.raise_for_status()
                try:
                    payload: Any = res.json()
                except ValueError:
                    payload = res.text
                # A StreamToken anywhere in the reply starts the stream, not a form field.
                reply = (await _stream_reply(cfg, payload, on_chunk, trace, body)
                         if cfg.stream_url or find_token(payload)[0]
                         else extract(payload, cfg.response_path))
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

        async def chat(prompt: str, on_chunk: Callable[[str], object] | None = None,
                       trace: list[str] | None = None) -> str:
            history.append({"role": "user", "content": prompt})
            body = _render(template, prompt, history)
            await ws.send(body)
            raw = await ws.recv()
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", "replace")
            _note(trace, f"WS {cfg.url}: sent prompt, reply received ({len(raw)} bytes)")
            try:
                payload: Any = json.loads(raw)
            except ValueError:
                payload = raw
            # The token comes back over the socket; the answer streams from SSE. If a
            # stream URL is configured but no token arrives, _stream_reply says so.
            reply = (await _stream_reply(cfg, payload, on_chunk, trace, body)
                     if cfg.stream_url or find_token(payload)[0]
                     else extract(payload, cfg.response_path))
            history.append({"role": "assistant", "content": reply})
            return reply

        yield chat
