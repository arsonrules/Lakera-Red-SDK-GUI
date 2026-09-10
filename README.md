# Lakera Red Runner

An interactive web service for triggering [Check Point AI Red Teaming](https://docs.lakera.ai/docs/red/sdk-quickstart)
(`lakera-red-sdk`) scans against any chat endpoint — fill in a form, watch the
attacks and your agent's replies stream live, read the verdicts.

* **Targets:** `http`, `https`, `ws`, `wss`
* **Auth:** none · bearer token · basic auth · API key header
* **TLS:** certificate verification is **off by default**, so self-signed certs,
  internal CAs and break-and-inspect proxies work without any setup — or turn it on
  and point **CA bundle** at your root CA. Both transports share one trust store.

## Run it

```bash
python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt
export LAKERA_RED_API_KEY=...            # or paste the key into the UI
.venv/bin/uvicorn app:app --port 8090
```

Open <http://localhost:8090>.

## Try it without a Red API key

A local echo agent plus a mock Red relay let you exercise the whole flow offline:

```bash
.venv/bin/python demo_servers.py
```

Then in the UI set **Base URL** to `http://127.0.0.1:8803`, **URL** to
`http://127.0.0.1:8801/chat` (or `ws://127.0.0.1:8801/ws`) and hit *Run scan*.

## Configuring a target

| Field | What it does |
|---|---|
| URL | `http(s)://…` for request/response endpoints, `ws(s)://…` for socket endpoints |
| Authentication | Credentials are sent as headers only — never in the URL |
| Verify TLS certificate | Leave off for self-signed / MITM-proxied endpoints; tick it to enforce validation |
| CA bundle | The root CA to trust — needed behind a TLS-inspection proxy or an internal PKI. Either a **path on the server** (a PEM/DER file, or a directory of them) or a certificate you **upload** through the UI. Setting it turns verification on |
| Request body template | `{{prompt}}` = the current attack, `{{messages}}` = the full `[{role,content}]` history |
| Response path | Dot path into the JSON reply, e.g. `choices.0.message.content`. Blank returns the whole body |
| Extra headers | JSON object merged into every request |

**Multi-turn scans.** `crescendo` escalates over several turns in one session. WS
targets get that for free — the socket is held open for the whole session. HTTP
targets are stateless, so use `{{messages}}` to send the history:

```json
{"model": "gpt-4o-mini", "messages": {{messages}}}
```

with response path `choices.0.message.content`.

## Target profile

A target owns a **recon profile** that Red uses to tailor its attacks, and it is
reused across scans ([docs](https://docs.lakera.ai/docs/red/sdk-how-tos/create-a-target)).
The form covers all the ways to set it:

* **Fill in the app description / allowed / forbidden actions** — the profile is set
  directly, no recon runs.
* **Leave them blank** — Red runs a short recon phase through your endpoint and
  saves what it discovers.
* **Paste a target id** — an existing target is reused as is; the name and context
  fields are ignored ([docs](https://docs.lakera.ai/docs/red/sdk-how-tos/reuse-a-target)).
* **Re-run recon before scanning** — refreshes a profile that has drifted out of
  date ([docs](https://docs.lakera.ai/docs/red/sdk-how-tos/keep-profile-up-to-date)).

**Ground truth** (the real system prompt and tool definitions) is optional and
makes the judge more precise, cutting false positives.

## HTTP API

| Endpoint | Purpose |
|---|---|
| `POST /api/probe` | Send one message to the target — connectivity and auth check |
| `POST /api/scans` | Start a scan; returns `{"run_id": …}` |
| `GET /api/scans/{id}` | Snapshot: status, scan id, dashboard link, results, logs |
| `GET /api/scans/{id}/events` | Server-sent events: live attacks, replies and status |
| `POST /api/scans/{id}/cancel` | Stop a running scan |
| `POST /api/tls-check` | Diagnose why an `https`/`wss` endpoint fails verification |
| `POST /api/ca` | Upload a CA bundle — `{"name":…, "pem":…}` or `{"name":…, "data_b64":…}` for DER |
| `GET /api/ca` | List stored bundles with the subjects each contains |
| `DELETE /api/ca/{name}` | Remove a stored bundle |
| `POST /api/ca/inspect` | List the certificates at a server-side path (file or directory) |
| `GET /api/objectives` | The objective catalogue |

## Using it as a CI gate

The service is outbound-only, so it runs on an ordinary CI runner
([docs](https://docs.lakera.ai/docs/red/sdk-how-tos/run-scans-in-ci-cd)). Start it
alongside your app, POST a scan, then fail closed — block on any flagged, errored
or unscored objective:

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

Keep a stable target name so runs stay comparable, run a small `static` scan on
every build and a deeper `crescendo` scan before a release.

## TLS problems

Hitting `CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate`?
Click **Diagnose TLS** in the UI, or:

```bash
.venv/bin/python tls_doctor.py https://your-endpoint.internal/chat
```

It names the issuer actually being presented and tells you what to do about it.
Once you know which root you need, supply it under **CA bundle** — either a path
on the server or by uploading the certificate. Uploads are validated, normalised
to PEM (DER accepted) and stored under `ca_store/`; set `LAKERA_RED_CA_STORE` to
put them elsewhere. See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for the full
walkthrough.

## Tests

```bash
.venv/bin/python test_all.py
```

83 checks against real local servers and a mock relay: all 16 transport × auth
combinations; certificate trust (self-signed, private CA, supplied CA bundle,
wrong bundle, missing bundle, and https/wss agreeing on the verdict); CA bundle
handling (a plain directory, mixed PEM/DER, uploads, path-traversal containment,
and junk/private keys refused); the TLS diagnosis across every failure mode; body templating and response extraction;
input validation; and full scans covering static, crescendo, smoke, custom
objectives, recon, target reuse, recon refresh, target failures and the SSE
stream.

## Notes

* The Red API key is read from the request or `LAKERA_RED_API_KEY`; it is never
  written to disk or into the run log.
* Runs are held in memory — restarting the service drops the history. The scan
  itself lives on the Red dashboard, which every run links to.
* Bind to localhost. Anyone who can reach this service can make it send traffic
  to arbitrary endpoints with credentials you have entered.
