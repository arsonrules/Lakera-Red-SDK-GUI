"""Diagnose why a TLS endpoint fails certificate verification.

Handshakes once with verification disabled to read the certificate the endpoint
actually presents, then re-tries verification against each candidate trust store
to work out which one (if any) would accept it -- turning
"unable to get local issuer certificate" into a named cause and a fix.
"""

from __future__ import annotations

import asyncio
import os
import re
import socket
import ssl
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Root CA names used by the common TLS-inspection products, to spot interception.
INTERCEPTORS = ("zscaler", "netskope", "bluecoat", "blue coat", "forcepoint", "mcafee",
                "palo alto", "fortinet", "fortigate", "sophos", "check point", "checkpoint",
                "cisco umbrella", "websense", "trustwave", "kaspersky", "eset", "bitdefender",
                "proxy", "mitm", "ssl inspection", "deep packet")


def _host_port(url: str) -> tuple[str, int]:
    parts = urlparse(url)
    if parts.scheme not in ("https", "wss"):
        raise ValueError(f"{parts.scheme or url!r} is not a TLS scheme — nothing to diagnose")
    return parts.hostname or "", parts.port or 443


def _name(rdn: Any) -> str:
    """Flatten getpeercert()'s nested subject/issuer tuples into a readable name."""
    if not rdn:
        return ""
    parts = {k: v for group in rdn for (k, v) in group}
    return parts.get("commonName") or parts.get("organizationName") or str(parts)


def _rdn_cn(text: str) -> str:
    """Pick the most identifying name out of an OpenSSL RDN line."""
    for key in ("CN", "O", "OU"):
        found = re.search(rf"\b{key}\s*=\s*([^,/\n]+)", text)
        if found:
            return found.group(1).strip()
    return text.strip()


def parse_der(der: bytes) -> dict[str, Any]:
    """Subject/issuer/expiry/SANs from a DER certificate.

    ssl.getpeercert() returns {} whenever the peer was not validated, which is
    exactly the case we need to describe, so the presented cert is parsed here
    instead. Best effort: cryptography if installed, else the openssl CLI, else
    nothing -- the verdict still falls back to the verification error text.
    """
    try:
        from cryptography import x509  # optional; not a declared dependency

        cert = x509.load_der_x509_certificate(der)
        try:
            sans = [str(n.value) for n in cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value]
        except x509.ExtensionNotFound:
            sans = []
        return {"subject": _rdn_cn(cert.subject.rfc4514_string()),
                "issuer": _rdn_cn(cert.issuer.rfc4514_string()),
                "not_after": cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT"),
                "sans": sans}
    except ImportError:
        pass
    except Exception:
        return {}

    try:
        proc = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer",
             "-enddate", "-ext", "subjectAltName"],
            input=der, capture_output=True, timeout=10,
        )
        out = proc.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return {}

    def line(prefix: str) -> str:
        found = re.search(rf"^{prefix}=(.*)$", out, re.M)
        return found.group(1).strip() if found else ""

    sans = re.findall(r"(?:DNS|IP Address):([^,\s]+)", out)
    return {"subject": _rdn_cn(line("subject")), "issuer": _rdn_cn(line("issuer")),
            "not_after": line("notAfter"), "sans": sans}


CERT_SUFFIXES = (".pem", ".crt", ".cer", ".der", ".cert", ".ca-bundle")
MAX_CA_BYTES = 2 * 1024 * 1024


def _to_pem(blob: bytes) -> list[str]:
    """Normalise one cert file's bytes to a list of PEM blocks (DER accepted)."""
    text = blob.decode("utf-8", "replace")
    if "-----BEGIN CERTIFICATE-----" in text:
        return [
            "-----BEGIN CERTIFICATE-----" + part.split("-----END CERTIFICATE-----")[0]
            + "-----END CERTIFICATE-----\n"
            for part in text.split("-----BEGIN CERTIFICATE-----")[1:]
            if "-----END CERTIFICATE-----" in part
        ]
    try:
        # DER_cert_to_PEM_cert base64-encodes whatever it is given without
        # validating, so the result is only kept if OpenSSL accepts it below.
        return [ssl.DER_cert_to_PEM_cert(blob)]
    except Exception:
        return []


def _is_certificate(pem: str) -> bool:
    """Authoritative check: would OpenSSL accept this as a trust anchor?"""
    try:
        ssl.create_default_context().load_verify_locations(cadata=pem)
        return True
    except (ssl.SSLError, ValueError, TypeError):
        return False


def read_ca_pems(path: str | Path) -> tuple[list[str], list[str]]:
    """Collect CA certificates from a PEM/DER file or a directory of them.

    OpenSSL's ``capath`` only finds certificates in a directory whose filenames
    are subject hashes (``c_rehash``); pointed at an ordinary folder of .pem
    files it silently trusts nothing and fails with the very same "unable to get
    local issuer certificate". So directories are read here instead, and the
    certificates are handed to the context as ``cadata``.

    Returns (pem blocks, human-readable subject names).
    """
    target = Path(path)
    if not target.exists():
        raise ValueError(f"CA bundle not found: {path}")

    files = (
        sorted(f for f in target.iterdir()
               if f.is_file() and (f.suffix.lower() in CERT_SUFFIXES or f.suffix == ".0"))
        if target.is_dir() else [target]
    )
    if not files:
        raise ValueError(f"No certificate files in {path} (looked for {', '.join(CERT_SUFFIXES)})")

    pems: list[str] = []
    total = 0
    for f in files:
        try:
            blob = f.read_bytes()
        except OSError as exc:
            raise ValueError(f"Cannot read {f}: {exc}") from exc
        total += len(blob)
        if total > MAX_CA_BYTES:
            raise ValueError(f"CA bundle exceeds {MAX_CA_BYTES // 1024} KB")
        pems.extend(pem for pem in _to_pem(blob) if _is_certificate(pem))

    if not pems:
        raise ValueError(
            f"No usable certificates in {path} — the file(s) parsed but OpenSSL "
            "rejected them. A CA bundle must be PEM or DER certificates."
        )

    names: list[str] = []
    for pem in pems:
        try:
            info = parse_der(ssl.PEM_cert_to_DER_cert(pem))
            names.append(info.get("subject") or "(unparsed certificate)")
        except Exception:
            names.append("(unparsed certificate)")
    return pems, names


def _stores(ca_bundle: str = "") -> list[tuple[str, ssl.SSLContext | None, str]]:
    """Candidate trust stores, in the order worth reporting."""
    out: list[tuple[str, ssl.SSLContext | None, str]] = []

    def ctx_for(**kw: str) -> ssl.SSLContext | None:
        try:
            return ssl.create_default_context(**kw)
        except Exception:
            return None

    if ca_bundle:
        def supplied() -> ssl.SSLContext | None:
            try:
                ctx = ssl.create_default_context()
                ctx.load_verify_locations(cadata="".join(read_ca_pems(ca_bundle)[0]))
                return ctx
            except Exception:
                return None

        out.append(("the CA bundle you supplied", supplied(), ca_bundle))
    if os.environ.get("SSL_CERT_FILE"):
        out.append(("$SSL_CERT_FILE", ctx_for(cafile=os.environ["SSL_CERT_FILE"]),
                    os.environ["SSL_CERT_FILE"]))
    out.append(("the OpenSSL system store", ctx_for(), ssl.get_default_verify_paths().cafile or "-"))
    try:
        import certifi

        out.append(("the certifi bundle (httpx's default)", ctx_for(cafile=certifi.where()),
                    certifi.where()))
    except ImportError:
        pass
    return out


def _handshake(host: str, port: int, ctx: ssl.SSLContext, timeout: float) -> dict[str, Any]:
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            return {"cert": tls.getpeercert(), "der": tls.getpeercert(binary_form=True),
                    "version": tls.version(), "cipher": (tls.cipher() or ["", "", ""])[0]}


def diagnose(url: str, ca_bundle: str = "", timeout: float = 10.0) -> dict[str, Any]:
    host, port = _host_port(url)
    report: dict[str, Any] = {"url": url, "host": host, "port": port,
                              "findings": [], "fixes": [], "stores": []}

    insecure = ssl.create_default_context()
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE
    try:
        seen = _handshake(host, port, insecure, timeout)
    except Exception as exc:
        report["reachable"] = False
        report["verdict"] = "no-handshake"
        report["findings"].append(f"Could not complete a TLS handshake at all: "
                                  f"{type(exc).__name__}: {exc}")
        report["fixes"].append("This is not a trust problem — check the host, port, and that the "
                               "endpoint really speaks TLS (an http:// service on this port would "
                               "fail exactly like this).")
        return report

    report["reachable"] = True
    report["tls_version"] = seen["version"]
    report["cipher"] = seen["cipher"]
    cert = seen["cert"] or {}
    parsed = parse_der(seen["der"]) if seen.get("der") else {}
    subject = parsed.get("subject") or _name(cert.get("subject"))
    issuer = parsed.get("issuer") or _name(cert.get("issuer"))
    report["certificate"] = {
        "subject": subject,
        "issuer": issuer,
        "not_after": parsed.get("not_after") or cert.get("notAfter"),
        "sans": parsed.get("sans") or [v for k, v in cert.get("subjectAltName", ())
                                       if k in ("DNS", "IP Address")],
        "self_signed": bool(subject) and subject == issuer,
    }

    for label, ctx, source in _stores(ca_bundle):
        if ctx is None:
            report["stores"].append({"store": label, "source": source, "accepts": False,
                                     "error": "could not load"})
            continue
        try:
            _handshake(host, port, ctx, timeout)
            report["stores"].append({"store": label, "source": source, "accepts": True})
        except ssl.SSLCertVerificationError as exc:
            report["stores"].append({"store": label, "source": source, "accepts": False,
                                     "error": exc.verify_message or str(exc)})
        except Exception as exc:
            report["stores"].append({"store": label, "source": source, "accepts": False,
                                     "error": f"{type(exc).__name__}: {exc}"})

    accepted = [s for s in report["stores"] if s["accepts"]]
    errors = " ".join((s.get("error") or "").lower() for s in report["stores"])

    if accepted:
        report["verdict"] = "verifiable"
        report["findings"].append(
            f"The chain verifies against {accepted[0]['store']} ({accepted[0]['source']}).")
        if any(not s["accepts"] for s in report["stores"]):
            report["findings"].append(
                "Other trust stores reject it, which is why the result depends on the transport.")
        report["fixes"].append("Verification can stay on. If it still fails in the app, set the CA "
                               f"bundle to {accepted[0]['source']}.")
        return report

    if report["certificate"]["self_signed"] or (
        "self-signed certificate" in errors and "in certificate chain" not in errors
    ):
        report["verdict"] = "self-signed"
        report["findings"].append(
            f"The endpoint presents a self-signed certificate"
            + (f" ({subject!r} issued by itself)" if subject else "")
            + ", so there is no CA that can vouch for it.")
        report["fixes"].append("Save that certificate as a .pem and set it as the CA bundle, or "
                               "leave 'Verify TLS certificate' off for this target.")
    elif "unable to get local issuer" in errors or "self-signed certificate in cert" in errors:
        report["verdict"] = "untrusted-issuer"
        report["findings"].append(
            f"The certificate for {subject!r} is issued by {issuer!r}, which is not in any trust "
            "store here — and the server did not send a chain reaching one.")
        if any(vendor in issuer.lower() for vendor in INTERCEPTORS):
            report["findings"].append(
                f"{issuer!r} looks like a TLS-inspection proxy: your traffic is being decrypted "
                "and re-signed in transit.")
            report["fixes"].append("Export that proxy's root CA as PEM and set it as the CA "
                                   "bundle. Your IT team publishes it; on macOS you can also "
                                   "export it from Keychain Access.")
        else:
            report["fixes"].append(f"Obtain the PEM for {issuer!r} (the issuing root, or the "
                                   "intermediate the server omitted) and set it as the CA bundle.")
            report["fixes"].append("If the issuer is a public CA, the server is misconfigured — it "
                                   "is not sending its intermediate certificate. Fix it there and "
                                   "every client benefits.")
    elif "expired" in errors:
        report["verdict"] = "expired"
        report["findings"].append(f"The certificate expired on {cert.get('notAfter')}.")
        report["fixes"].append("Renew it on the endpoint.")
    elif "hostname mismatch" in errors or "doesn't match" in errors:
        report["verdict"] = "hostname-mismatch"
        report["findings"].append(
            f"The certificate is valid for {report['certificate']['sans']}, not {host!r}.")
        report["fixes"].append("Connect using a name the certificate covers.")
    else:
        report["verdict"] = "rejected"
        report["findings"].append(f"Verification failed: {errors.strip() or 'unknown reason'}")
        report["fixes"].append("Set the CA bundle to the issuing root CA in PEM form.")

    report["fixes"].append("Turning verification off is a valid last resort for a target you own, "
                           "but it also hides a real interception you may want to know about.")
    return report


async def adiagnose(url: str, ca_bundle: str = "", timeout: float = 10.0) -> dict[str, Any]:
    return await asyncio.to_thread(diagnose, url, ca_bundle, timeout)


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        sys.exit("usage: python tls_doctor.py <https-or-wss-url> [ca-bundle.pem]")
    print(json.dumps(diagnose(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else ""), indent=2))
