# `CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate`

```
SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED]
certificate verify failed: unable to get local issuer certificate (_ssl.c:1010)
```

## Root cause

The endpoint presents a certificate that **cannot be chained to any root CA this
service trusts**. OpenSSL walked up from the server's leaf certificate looking for
an issuer it recognises, ran out of chain, and stopped.

This is *not* the same as the self-signed error, and the difference tells you what
went wrong:

| OpenSSL says | X509 code | Means |
|---|---|---|
| `self-signed certificate` | 18 | The leaf signed itself — no CA involved at all |
| **`unable to get local issuer certificate`** | **20** | **The leaf was signed by someone, but that issuer is unknown here** |

Three things produce code 20, in rough order of likelihood:

1. **A TLS-inspection proxy** (Zscaler, Netskope, Palo Alto, Check Point, Forcepoint…).
   Corporate egress decrypts your traffic and re-signs it with a private root. The
   Lakera deployment docs describe exactly this case and prescribe trusting that CA
   — `NODE_EXTRA_CA_CERTS` for the Node SDK; the Python equivalent is a CA bundle.
2. **An internal PKI** — the endpoint uses your organisation's own CA.
3. **A server that omits its intermediate certificate.** The root is public and
   trusted, but the server never sends the intermediate that links to it, so the
   chain cannot be built. Browsers often paper over this by caching intermediates;
   Python does not.

### Two contributing defects in this service, now fixed

**No way to supply a CA bundle.** `verify_tls` was a boolean. Behind an
inspection proxy your only options were "broken" or "verification off" — the
insecure choice was the *only working* choice. There is now a **CA bundle** field
(and `ca_bundle` in the API) that trusts a specific root.

**HTTPS and WSS used different trust stores.** `httpx` verifies against
certifi's roots, while `ssl.create_default_context()` verifies against OpenSSL's.
On this machine that is 121 roots versus 191 — so the *same* endpoint could verify
over `https://` and fail over `wss://`. Both transports now share one context
built by `build_ssl_context()`.

> The reported exception type is itself a clue: `httpx` wraps TLS failures in
> `ConnectError`, while `websockets` surfaces the raw `SSLCertVerificationError`.
> A bare `SSLCertVerificationError` means the target was `wss://`.

## Troubleshooting plan

### 1. Diagnose — don't guess

In the UI, click **Diagnose TLS**, or:

```bash
.venv/bin/python tls_doctor.py https://your-endpoint.internal/chat
```

It handshakes with verification off to read the certificate actually presented,
then re-tries against every candidate trust store, and reports a verdict:

| Verdict | Meaning | Fix |
|---|---|---|
| `untrusted-issuer` | Issuer unknown here (your error) | Trust the issuing root — step 2 |
| `self-signed` | Leaf signed itself | Trust that cert, or leave verification off |
| `verifiable` | Some store accepts it | Point `ca_bundle` at the store it names |
| `hostname-mismatch` | Cert not valid for this host | Use a name the cert covers |
| `expired` | Past `notAfter` | Renew on the endpoint |
| `no-handshake` | Not a trust problem | Wrong port, or plain HTTP behind `https://` |

The report names the **issuer**, which is the whole game — if it reads
`Zscaler Root CA` you are being intercepted; if it reads a public CA like
`DigiCert…`, the server is failing to send its intermediate.

### 2. Get the issuing root as PEM

```bash
# Whatever the endpoint presents, chain included
openssl s_client -showcerts -connect your-endpoint.internal:443 </dev/null

# macOS: export the proxy root your org installed
security find-certificate -a -c "Zscaler" -p /Library/Keychains/System.keychain > corp-root-ca.pem

# Linux: it is usually already dropped here by your config management
ls /usr/local/share/ca-certificates/ /etc/pki/ca-trust/source/anchors/
```

Verify the PEM really is the issuer before trusting it:

```bash
openssl verify -CAfile corp-root-ca.pem <(openssl s_client -showcerts \
  -connect your-endpoint.internal:443 </dev/null 2>/dev/null)
```

### 3. Apply it

In the UI, **CA bundle** offers two routes:

* **Path on the server** — a PEM/DER file, or a *directory* of them. Click
  **Inspect** to confirm which certificates were found before you rely on it.
* **Upload a certificate** — pick a `.pem`/`.crt`/`.cer`/`.der` file or paste PEM
  text. It is validated, converted to PEM, and stored under `ca_store/`
  (`LAKERA_RED_CA_STORE` to relocate). Anything that is not a certificate — a
  private key, a config file — is refused rather than stored.

> A directory is read directly rather than handed to OpenSSL's `capath`, which
> only finds certificates whose filenames are subject hashes (`c_rehash`).
> Pointed at an ordinary folder of `.pem` files, `capath` trusts nothing and
> fails with this very same error — so the service does not use it.

Or per target through the API:

```json
{"target": {"url": "wss://your-endpoint.internal/ws", "ca_bundle": "/etc/ssl/certs/corp-root-ca.pem"}}
```

Service-wide, for every outbound call including the SDK's own traffic to
`red-webhooks.lakera.ai` — which needs the same trust behind an inspecting proxy:

```bash
export SSL_CERT_FILE=/etc/ssl/certs/corp-root-ca.pem
.venv/bin/uvicorn app:app --port 8090
```

Setting `ca_bundle` implies verification is on. It **replaces** the default roots
rather than adding to them, so if the endpoint's chain is public but your Red API
traffic is intercepted, bundle both:

```bash
cat corp-root-ca.pem "$(.venv/bin/python -m certifi)" > /etc/ssl/certs/combined.pem
```

### 4. If the issuer is a *public* CA

Then nothing is intercepting you — the server is misconfigured and is not sending
its intermediate. Fix it at the endpoint (every client benefits); as a stopgap,
put the intermediate in the CA bundle.

### 5. Last resort

Untick **Verify TLS certificate**. Legitimate for a scratch target you own with a
self-signed cert. Understand what you give up: an unverified connection cannot
distinguish your endpoint from anything sitting in front of it, and the attack
prompts and your agent's replies both traverse that connection.

## Quick reference

| Symptom | Likely cause |
|---|---|
| `unable to get local issuer certificate` | Private/unknown issuer, or missing intermediate |
| `self-signed certificate` | Leaf signed itself |
| `self-signed certificate in certificate chain` | A private root *was* sent but is not trusted |
| Works on `https://`, fails on `wss://` (or vice versa) | Trust-store split — fixed; upgrade |
| `no-handshake` / connection refused | Wrong port, or the service is plain HTTP |
| Works in `curl`, fails here | `curl` uses the system store; set `SSL_CERT_FILE` |
