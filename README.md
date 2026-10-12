# Lakera Red Runner

A web UI and small API for running [Check Point AI Red Teaming](https://docs.lakera.ai/docs/red/sdk-quickstart)
(`lakera-red-sdk`) scans against any chat endpoint. Fill in the target, start a scan,
and watch the attacks and your agent's replies as they happen. When the scan finishes,
read the verdicts and export them.

- **Targets:** `http`, `https`, `ws`, `wss`, including targets that stream their answer
  over SSE after handing back a `StreamToken`
- **Auth:** none, bearer token, basic auth, or an API key header
- **TLS:** verification is **off by default**, so self-signed certificates, internal CAs
  and break-and-inspect proxies work without setup. Turn it on and point **CA bundle** at
  your root CA when you want validation. Both transports share one trust store.

## Quick start

```bash
python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt
export LAKERA_RED_API_KEY=...          # or paste the key into the UI
.venv/bin/uvicorn app:app --port 8090
```

Open <http://localhost:8090>.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `LAKERA_RED_API_KEY` | none | Red API key, used when the key field is left blank |
| `LAKERA_RED_BASE_URL` | `https://red-webhooks.lakera.ai` | Red API endpoint. Only override for a non-production environment |
| `LAKERA_RED_CA_STORE` | `ca_store/` | Where uploaded CA bundles are stored |
| `SSL_CERT_FILE` / `SSL_CERT_DIR` | unset | When verification is on and no CA bundle is set, these replace the default roots. Used by the TLS diagnosis and connection test as well |

`.env.example` lists the first two.

## Try it without a Red API key

A local echo agent and a mock Red relay let you run the whole flow offline:

```bash
.venv/bin/python demo_servers.py
```

In the UI, set **Lakera Red API URL** to `http://127.0.0.1:8803`, **URL** to
`http://127.0.0.1:8801/chat` (or `ws://127.0.0.1:8801/ws`), and press **Run scan**.
For a streaming target, use URL `http://127.0.0.1:8801/sse-chat` with **SSE stream URL**
`http://127.0.0.1:8801/sse`.

## Using the UI

The page has two views. On a narrow screen they appear as the **Configure** and **Run**
tabs. On a wide screen they sit side by side.

**Configure** is a set of collapsible sections. Each collapsed header shows a one-line
summary, such as `wss · apiai.example.com · bearer token`:

- **Red API:** the key and the API URL.
- **Connection:** URL and authentication.
- **Request:** HTTP method, body template and extra headers. Ignored fields are hidden
  for ws targets.
- **Response:** response path and SSE stream URL.
- **TLS:** verification, CA bundle and **Diagnose TLS**.
- **Target profile:** target name or id, app description, allowed and forbidden actions,
  and ground truth.
- **Scan:** strategy, concurrency, timeout, language and objectives.

Sections with an error open automatically, and the field is focused.

**Checks as you type.** The form flags problems before you run:

- a URL in **Response path** (it is a dot path, not a URL);
- an unknown `{{…}}` placeholder in the body (only `{{prompt}}` and `{{messages}}` are filled in);
- an invalid scheme, JSON in headers or custom objectives, and a non-http SSE stream URL.

A pasted link such as `[text](url)`, or a JavaScript token expression such as
`${encodeURIComponent(streamToken)}`, is converted to a plain URL and `{StreamToken}`,
and the form says what it changed.

**Test connection** sends one message through the target and lists each step: the
POST status, whether a token was found and where, which stream URL was chosen, the SSE
status, and how many events carried text. The header keeps the last result. Editing the
target afterwards marks it as stale.

**Saved configs and templates.** Save any form as a named config, then load, export,
import or delete it. Three starter templates fill in the request and response fields:
plain JSON POST, OpenAI-compatible chat, and WebSocket → SSE. Saved configs, exports and
the remembered form never include the API key, bearer token, password or pasted PEM text.
Extra headers and the request body are saved, so keep credentials out of them.

**Objectives.** Filter the list, select a whole category with its checkbox, and see how
many are selected. None selected means all objectives run. Smoke scans ignore this.

### The run view

- **Status bar:** state, elapsed time, the scan name and target, a link to the Lakera
  dashboard, and **Cancel**. **Recent runs** lists runs from this server session.
- **Progress:** conversations (with how many are still open), attacks, replies, errors
  and timeouts.
- **Conversations:** one card per session, with attacks and replies as chat bubbles. A
  streamed reply grows in place.
- **Raw log:** every log line with its fields, filterable by level. Session open and
  close lines can be hidden.
- **Results:** a verdict summary, a table you can sort and filter, and a row to expand for
  the explanation and the full conversation. **Export** writes JSON, CSV or a Markdown
  report from the results on the page.

A reload during a scan reattaches to it. If the connection to the server drops, a banner
says so and offers the run in **Recent runs**.

**Verdicts fail closed.** A run is **safe** only when every objective was scored and none
got through. Any objective marked **malicious** makes the run malicious. Objectives that
errored, timed out or went unscored make it **inconclusive**.

**Keyboard and theme.** `Ctrl`/`⌘` + `Enter` runs the scan. `/` jumps to the objective
filter, unless you are typing in a field. The theme button cycles system, light and dark.

## Target fields

| Field | What it does |
|---|---|
| URL | `http(s)://…` for request/response endpoints, `ws(s)://…` for socket endpoints |
| Authentication | Credentials are sent as headers only, never in the URL |
| Verify TLS certificate | Leave off for self-signed or MITM-proxied endpoints. Tick it to enforce validation |
| CA bundle | The root CA to trust, for a TLS-inspection proxy or an internal PKI. Either a **path on the server** (a PEM or DER file, or a directory of them), or a certificate **uploaded** through the UI. Setting it turns verification on, and the CA is added to the default roots |
| Request body template | `{{prompt}}` is the current attack. `{{messages}}` is the full `[{role,content}]` history |
| Response path | Dot path into the JSON reply, e.g. `choices.0.message.content`. Blank returns the whole body. For an SSE target it points inside each event instead (blank means `content`) |
| SSE stream URL | Where the stream lives, e.g. `https://host/path/to/{StreamToken}`. The retrieved token replaces `{StreamToken}`, or is appended if the URL has no placeholder. Optional for http targets. Required for ws/wss targets |
| Extra headers | A JSON object merged into every request |

**Multi-turn scans.** `crescendo` escalates over several turns in one session. WebSocket
targets keep the socket open for the whole session. HTTP targets are stateless, so send
the history with `{{messages}}`:

```json
{"model": "gpt-4o-mini", "messages": {{messages}}}
```

with response path `choices.0.message.content`.

## Streaming (SSE) targets

Some targets return a token instead of the answer, and stream the text from an SSE
endpoint. A reply carrying a `StreamToken` switches each turn to the streaming flow.
This includes the connection test and replies that arrive over a **WebSocket**. The
token comes back over the socket, and the answer streams from the https endpoint you
give under **SSE stream URL**. A ws target's reply names only the token, so that field
is required for ws/wss. An http target can fall back to a URL in its reply, or to its
own URL.

1. The prompt goes to the target URL with the configured auth, CA bundle and body.
2. The `StreamToken` is read from the JSON reply. `message.StreamToken` is preferred,
   then the shallowest `StreamToken` anywhere in the reply. Key names match ignoring case
   and separators, and objects nested as JSON strings are opened.
3. The stream is opened with `GET`, with the token put where `{StreamToken}` is written.
   The token is URL-encoded, the query string is kept, and the request uses the same TLS
   trust, auth and extra headers. The stream URL is **SSE stream URL** if set, otherwise a
   `StreamUrl` or `SseUrl` the reply names, otherwise the target URL. An endpoint that
   answers `405` to `GET` is retried as `POST`. If a TLS target's stream URL is plaintext
   `http` and the connection fails, the stream is retried over `https`.
4. Each event's `content` is appended as it arrives. The configured **Response path** is
   tried first, then any `content` key, so `choices.0.delta.content` works unconfigured.
   An event that packs several JSON documents is read as each in turn. Comments, events
   without `content`, `null` content and malformed JSON are skipped. The stream ends at
   `data: [DONE]` or when the server closes it.
5. The joined text is the reply Red judges, so the verdict covers what a user would have
   seen streamed.

The connection test reports each step, so a stream that won't open says where it stopped.
A reply with no `StreamToken` fails that turn and lists the key paths the reply did hold.
The token is never shown in the UI, written to the run log, or sent to Red in an error.

## Target profile

A target owns a **recon profile** that Red uses to tailor its attacks, and it is reused
across scans ([docs](https://docs.lakera.ai/docs/red/sdk-how-tos/create-a-target)). The
form covers all the ways to set it:

- **Fill in the app description and allowed or forbidden actions.** The profile is set
  directly, and no recon runs.
- **Leave them blank.** Red runs a short recon phase through your endpoint and saves what
  it finds.
- **Paste a target id.** An existing target is reused as it is, and the name and context
  fields are ignored ([docs](https://docs.lakera.ai/docs/red/sdk-how-tos/reuse-a-target)).
- **Re-run recon before scanning.** Refreshes a profile that has drifted
  ([docs](https://docs.lakera.ai/docs/red/sdk-how-tos/keep-profile-up-to-date)).

**Ground truth** (the real system prompt and tool definitions) is optional. It makes the
judge more precise and cuts false positives.

## HTTP API

| Endpoint | Purpose |
|---|---|
| `POST /api/probe` | Send one message to the target. Connectivity and auth check. For an SSE target the reply is the joined stream, and `chunks` counts its pieces |
| `POST /api/scans` | Start a scan. Returns `{"run_id": …}` |
| `GET /api/scans` | List runs from this server session, newest first, with name and target URL |
| `GET /api/scans/{id}` | Snapshot: status, name, target, scan id, dashboard link, results, logs |
| `GET /api/scans/{id}/events` | Server-sent events: live logs and status. Replays the run from the start on each connection |
| `POST /api/scans/{id}/cancel` | Stop a running scan |
| `POST /api/tls-check` | Diagnose why an `https` or `wss` endpoint fails verification |
| `POST /api/ca` | Upload a CA bundle. `{"name":…, "pem":…}`, or `{"name":…, "data_b64":…}` for DER |
| `GET /api/ca` | List stored bundles with the subjects each contains |
| `DELETE /api/ca/{name}` | Remove a stored bundle |
| `POST /api/ca/inspect` | List the certificates at a server-side path (file or directory) |
| `GET /api/objectives` | The objective catalogue |

The run listing shows the target URL with credentials and query string removed.

## Using it as a CI gate

The service only makes outbound calls, so it runs on an ordinary CI runner
([docs](https://docs.lakera.ai/docs/red/sdk-how-tos/run-scans-in-ci-cd)). Start it next to
your app, POST a scan, and fail closed. The job blocks on any malicious, errored or
unscored objective:

```bash
.venv/bin/uvicorn app:app --port 8090 &
RUN=$(curl -sX POST localhost:8090/api/scans -H 'Content-Type: application/json' \
      -d @scan.json | .venv/bin/python -c 'import sys,json;print(json.load(sys.stdin)["run_id"])')
.venv/bin/python - "$RUN" <<'EOF'
import json, sys, time, urllib.request
url = f"http://localhost:8090/api/scans/{sys.argv[1]}"
while (run := json.load(urllib.request.urlopen(url)))["status"] not in ("done", "error", "cancelled"):
    time.sleep(5)
entries = (run.get("results") or {}).get("results") or []
json.dump(run.get("results"), open("red-scan-results.json", "w"), indent=2)
print("report:", run.get("dashboard_link"))
bad = [e for e in entries if e.get("isSuccessful") or e.get("error")
       or (e.get("evaluation") or {}).get("attackSuccessScore") is None]
for e in bad:
    print("blocked by", e["objectiveId"], file=sys.stderr)
sys.exit(1 if bad or run["status"] != "done" or not entries else 0)
EOF
```

Keep a stable target name so runs stay comparable. Run a small `static` scan on every
build, and a deeper `crescendo` scan before a release.

**Per-objective timeout.** Each objective runs over its own SSE stream, opened fresh and
closed when the objective finishes, errors, is cancelled or times out. Set
`objective_timeout` (seconds) in the request, or the **Per-objective timeout** field, to
cap how long each objective waits for the target. On expiry the turn is cancelled, the
objective is marked **timeout**, and the scan moves on. Leave it blank to wait as long as
needed.

## TLS problems

Seeing `CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate`? Click
**Diagnose TLS** in the UI, or run:

```bash
.venv/bin/python tls_doctor.py https://your-endpoint.internal/chat
```

It names the issuer being presented and says what to do. Once you know which root you
need, supply it under **CA bundle**, either as a server path or by uploading it. Uploads
are validated, normalised to PEM (DER is accepted) and stored under `ca_store/`. Set
`LAKERA_RED_CA_STORE` to store them elsewhere. See [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
for the full walkthrough.

## Tests

```bash
.venv/bin/python test_all.py
```

The server suite runs against real local servers and a mock relay. It covers:

- all transport and auth combinations, and certificate trust (self-signed, private CA,
  supplied bundle, wrong bundle, missing bundle, and https and wss agreeing on the verdict);
- CA bundle handling: directories, mixed PEM and DER, uploads, path containment, and
  junk or private keys refused;
- the TLS diagnosis across its failure modes;
- body templating, response extraction and input validation, including the URL-in-path
  and unknown-placeholder refusals;
- full scans: static, crescendo, smoke, custom objectives, recon, target reuse, recon
  refresh, target failures, and run listing;
- streaming targets: the StreamToken hand-off, SSE framing edge cases, each failure mode,
  verdicts on the streamed reply, and no token leaking;
- the per-objective SSE lifecycle and the optional timeout.

The browser test is `ui_tests.js`. It exercises the page itself: layout at desktop and
phone width, accessibility basics, field checks, the connection test, TLS diagnosis,
saved configs and templates, the objective picker, runs, results, export, history and
reattach, and the theme. It needs `demo_servers.py` running. Serve the file, load the
page, and run this in the browser console:

```js
const s = document.createElement("script");
s.src = "<url-of-ui_tests.js>";
document.head.append(s);
// after the script loads:
await uiTests();                 // then reload the page
await uiTestsAfterReload();      // checks what the browser remembered
```

## Notes

- The Red API key is read from the form or `LAKERA_RED_API_KEY`. It is never written to
  disk or to the run log.
- Target secrets go out as headers only. A value with a stray newline or space is refused
  by header name, because the HTTP library would otherwise quote it in its error. The Red
  API key is trimmed for the same reason.
- Runs are kept in memory, so restarting the service clears the history. The scan itself
  stays on the Red dashboard, and every run links to it.
- Bind to localhost. Anyone who can reach this service can make it send traffic to
  arbitrary endpoints with credentials you have entered.
