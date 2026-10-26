#!/usr/bin/env python3
"""ct-monitor: report new Certificate Transparency issuances for a domain.

Queries the Cert Spotter (SSLMate) issuances API, remembers what it has already
reported, and appends one ECS-style JSON document per *new* certificate to an
NDJSON file that Elastic Agent (Filestream) ships to Elasticsearch.

Usage:
    ct-monitor example.com
    ct-monitor example.com other.org --allowed-issuers "Let's Encrypt"
    ct-monitor example.com --dry-run          # list certs, change nothing

Standard library only.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

__version__ = "1.1.0"

DEFAULT_API = "https://api.certspotter.com/v1/issuances"
DEFAULT_STATE_DIR = "/var/lib/ct-monitor"
DEFAULT_OUT = "/var/log/ct-monitor/ct.ndjson"

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")

# Overridable in tests.
_sleep = time.sleep


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def log(msg: str) -> None:
    print(f"{now_iso()} ct-monitor: {msg}", file=sys.stderr)


def normalize_domain(raw: str) -> str:
    """Lowercase, strip dots/wildcards, IDNA-encode, validate.

    The domain ends up in file names, so anything odd is rejected.
    """
    d = raw.strip().lower().lstrip("*.").strip(".")
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid domain {raw!r}: {exc}") from exc
    if not DOMAIN_RE.match(d):
        raise ValueError(f"invalid domain {raw!r}")
    return d


def iso(ts):
    """Cert Spotter returns offsets like '-00:00'; normalise to 'Z' for Elasticsearch."""
    if not ts:
        return None
    return re.sub(r"[-+]00:?00$", "Z", ts)


def _retry_after(err: urllib.error.HTTPError):
    try:
        return int(err.headers.get("Retry-After", ""))
    except (TypeError, ValueError):
        return None


def fetch_page(api_url, domain, after, token, timeout=30, retries=4):
    """Fetch one page of issuances (oldest first, after the given issuance id)."""
    params = [
        ("domain", domain),
        ("include_subdomains", "true"),
        ("expand", "dns_names"),
        ("expand", "issuer"),
    ]
    if after is not None:
        params.append(("after", str(after)))
    headers = {"User-Agent": f"ct-monitor/{__version__}", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{api_url}?{urllib.parse.urlencode(params)}", headers=headers)

    for attempt in range(retries):
        last = attempt == retries - 1
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:  # must precede URLError
            if exc.code in (429, 500, 502, 503, 504) and not last:
                wait = _retry_after(exc) or (2 ** attempt) * 5
                log(f"HTTP {exc.code}, retrying in {min(wait, 120)}s")
                _sleep(min(wait, 120))
                continue
            raise
        except (urllib.error.URLError, TimeoutError):
            if last:
                raise
            _sleep((2 ** attempt) * 5)
    return []  # unreachable


def load_state(path: Path) -> dict:
    if path.exists():
        state = json.loads(path.read_text())
        state.setdefault("cursor", None)
        state.setdefault("seen", [])
        state.setdefault("baseline_done", False)
        return state
    return {"cursor": None, "seen": [], "baseline_done": False}


def save_state(path: Path, state: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state))
    os.replace(tmp, path)  # atomic


def append_lines(path: Path, docs) -> None:
    """Append documents with O_APPEND + fsync (safe with concurrent instances)."""
    if not docs:
        return
    data = memoryview(
        "".join(json.dumps(d, separators=(",", ":")) + "\n" for d in docs).encode()
    )
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        while data:
            written = os.write(fd, data)
            data = data[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


DN_KEYS = {
    "C": "country", "O": "organization", "OU": "organizational_unit", "CN": "common_name",
    "L": "locality", "ST": "state_or_province",
}


def parse_dn(dn):
    """Split 'C=SE, O=Telia Company AB, CN=Telia RSA OV CA v4' into ECS x509.issuer.* arrays."""
    out = {}
    for part in re.split(r"(?<!\\),\s*", dn or ""):
        key, sep, val = part.partition("=")
        field = DN_KEYS.get(key.strip().upper())
        val = val.replace("\\,", ",").strip()
        if sep and field and val:
            out.setdefault(field, []).append(val)
    return out


def prune(obj):
    """Drop None / empty values recursively so documents only carry real data."""
    if isinstance(obj, dict):
        cleaned = {k: prune(v) for k, v in obj.items()}
        return {k: v for k, v in cleaned.items() if v not in (None, "", [], {})}
    return obj


def build_event(domain, row, baseline, allowed_re):
    """Build one ECS-style document.

    The certificate is described with ECS TLS/x509 fields (tls.server.*, the certificate
    the monitored host would present). x509 is not a top-level ECS field set, so it lives
    under tls.server.x509. Tool-specific fields stay under the custom `ct` namespace.
    """
    issuer = row.get("issuer") or {}
    issuer_dn = issuer.get("name")
    issuer_name = issuer.get("friendly_name") or issuer_dn or "unknown"
    unexpected = None
    if allowed_re is not None:
        unexpected = not allowed_re.search(f"{issuer_name} {issuer_dn or ''}")

    sans = row.get("dns_names") or []
    cert_sha = (row.get("cert_sha256") or "").upper()  # ECS asks for uppercase hashes
    not_before, not_after = iso(row.get("not_before")), iso(row.get("not_after"))
    related_hash = [cert_sha] if cert_sha else []

    return prune({
        "@timestamp": now_iso(),
        "message": f"New certificate in CT logs for {domain} issued by {issuer_name}",
        "event": {
            "kind": "event",
            "category": ["network"],
            "type": ["info"],
            "action": "certificate-issued",
            "id": None if row.get("id") is None else str(row["id"]),
            "provider": "certspotter",
            "dataset": "ct.monitor",
        },
        "tls": {
            "server": {
                "issuer": issuer_dn,
                "not_before": not_before,
                "not_after": not_after,
                "hash": {"sha256": cert_sha},
                "x509": {
                    "alternative_names": sans,
                    "not_before": not_before,
                    "not_after": not_after,
                    "issuer": {"distinguished_name": issuer_dn, **parse_dn(issuer_dn)},
                },
            },
        },
        "related": {"hosts": sorted({domain, *sans}), "hash": related_hash},
        "ct": {
            "monitored_domain": domain,
            "issuer": issuer_name,
            "tbs_sha256": row.get("tbs_sha256"),
            "baseline": baseline,
            "issuer_unexpected": unexpected,  # None (omitted) when no allowlist is configured
        },
    })


def format_text(doc) -> str:
    ct, x = doc["ct"], doc["tls"]["server"]["x509"]
    sans = x.get("alternative_names", [])
    names = ",".join(sans[:4]) + ("…" if len(sans) > 4 else "")
    flag = {True: "UNEXPECTED-ISSUER", False: "expected-issuer", None: ""}[ct.get("issuer_unexpected")]
    return f"{doc['event']['id']}\t{x.get('not_before')}\t{ct['issuer']}\t{names}\t{flag}".rstrip()


def run_domain(domain, *, api_url, token, allowed_re, state_dir, out,
               skip_baseline=False, dry_run=False, as_json=False, max_pages=100):
    """Process one domain. Returns the number of documents emitted."""
    state_path = state_dir / f"{domain}.json"
    lock = None
    if not dry_run:
        state_dir.mkdir(parents=True, exist_ok=True)
        out.parent.mkdir(parents=True, exist_ok=True)
        lock = open(state_dir / f"{domain}.lock", "w")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log(f"{domain}: another run is in progress, skipping")
            return 0
    try:
        try:
            state = load_state(state_path)
        except OSError:
            if not dry_run:
                raise
            state = {"cursor": None, "seen": [], "baseline_done": False}
        seen = set(state["seen"])
        baseline = not state["baseline_done"]
        emitted = 0
        complete = False

        for _ in range(max_pages):
            page = fetch_page(api_url, domain, state["cursor"], token)
            if not page:
                complete = True
                break
            docs = []
            for row in page:
                key = row.get("tbs_sha256") or row.get("cert_sha256") or str(row.get("id"))
                if key in seen:
                    continue
                seen.add(key)
                if baseline and skip_baseline:
                    continue
                docs.append(build_event(domain, row, baseline, allowed_re))
            if dry_run:
                for d in docs:
                    print(json.dumps(d) if as_json else format_text(d))
            else:
                append_lines(out, docs)  # output first, then state: a crash duplicates, never loses
            emitted += len(docs)
            new_cursor = page[-1]["id"]
            if new_cursor == state["cursor"]:
                log(f"{domain}: cursor did not advance, stopping")
                break
            state["cursor"] = new_cursor
            state["seen"] = sorted(seen)
            if not dry_run:
                save_state(state_path, state)
        else:
            log(f"{domain}: reached --max-pages={max_pages}, remaining issuances will be read next run")

        if complete and not state["baseline_done"] and not dry_run:
            state["baseline_done"] = True
            state["seen"] = sorted(seen)
            save_state(state_path, state)

        log(f"{domain}: emitted={emitted} baseline={baseline} complete={complete} dry_run={dry_run}")
        return emitted
    finally:
        if lock:
            lock.close()


def parse_args(argv=None):
    env = os.environ.get
    ap = argparse.ArgumentParser(
        description="Report new Certificate Transparency issuances for one or more domains.")
    ap.add_argument("domains", nargs="+", help="domain(s) to monitor (subdomains are included)")
    ap.add_argument("--allowed-issuers", default=env("CT_ALLOWED_ISSUERS", ""),
                    help="regex of expected issuers; others get ct.issuer_unexpected=true "
                         "(env: CT_ALLOWED_ISSUERS)")
    ap.add_argument("--state-dir", default=env("CT_STATE_DIR", DEFAULT_STATE_DIR),
                    help=f"state directory (default {DEFAULT_STATE_DIR}; env: CT_STATE_DIR)")
    ap.add_argument("--out", default=env("CT_OUT", DEFAULT_OUT),
                    help=f"NDJSON output file (default {DEFAULT_OUT}; env: CT_OUT)")
    ap.add_argument("--api-url", default=env("CT_API_URL", DEFAULT_API), help=argparse.SUPPRESS)
    ap.add_argument("--skip-baseline", action="store_true",
                    help="on the first run record existing certs as seen without emitting events")
    ap.add_argument("--max-pages", type=int, default=100,
                    help="max API pages per run per domain (default 100, ~100 certs each)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would be reported; write no state and no output file")
    ap.add_argument("--json", action="store_true", help="with --dry-run: print full JSON documents")
    ap.add_argument("--version", action="version", version=f"ct-monitor {__version__}")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        domains = [normalize_domain(d) for d in args.domains]
        allowed_re = re.compile(args.allowed_issuers, re.I) if args.allowed_issuers else None
    except (ValueError, re.error) as exc:
        print(f"ct-monitor: {exc}", file=sys.stderr)
        return 2

    token = os.environ.get("CERTSPOTTER_TOKEN")
    rc = 0
    for domain in domains:
        try:
            run_domain(
                domain, api_url=args.api_url, token=token, allowed_re=allowed_re,
                state_dir=Path(args.state_dir), out=Path(args.out),
                skip_baseline=args.skip_baseline, dry_run=args.dry_run,
                as_json=args.json, max_pages=args.max_pages)
        except urllib.error.HTTPError as exc:
            log(f"{domain}: API error HTTP {exc.code}")
            rc = 1
        except (urllib.error.URLError, TimeoutError) as exc:
            log(f"{domain}: request failed: {exc}")
            rc = 1
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            log(f"{domain}: {type(exc).__name__}: {exc}")
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
