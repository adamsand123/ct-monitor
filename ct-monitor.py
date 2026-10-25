#!/usr/bin/env python3
"""Emit new Certificate Transparency issuances for a domain as ECS-style NDJSON.

Usage: ct-monitor.py example.com [--allowed-issuers REGEX] [--skip-baseline]
Env:   CERTSPOTTER_TOKEN (optional API token)
"""
import argparse, fcntl, json, os, re, sys, time
import urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone
from pathlib import Path

API = "https://api.certspotter.com/v1/issuances"


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def fetch(domain, after, token):
    params = [("domain", domain), ("include_subdomains", "true"),
              ("expand", "dns_names"), ("expand", "issuer")]
    if after:
        params.append(("after", after))
    req = urllib.request.Request(f"{API}?{urllib.parse.urlencode(params)}",
                                 headers={"User-Agent": "ct-monitor/1.0"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
        print("token:" + token)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 2:
                try:
                    wait = int(e.headers.get("Retry-After", "30"))
                except ValueError:
                    wait = 30
                time.sleep(min(wait, 120))
                continue
            raise


def load_state(path):
    if path.exists():
        return json.loads(path.read_text())
    return {"cursor": None, "seen": []}


def save_state(path, state):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state))
    os.replace(tmp, path)          # atomic


def build_event(domain, row, baseline, allowed):
    issuer = row.get("issuer") or {}
    issuer_name = issuer.get("friendly_name") or issuer.get("name") or "unknown"
    unexpected = None
    if allowed:
        unexpected = not re.search(allowed, f"{issuer_name} {issuer.get('name', '')}", re.I)
    return {
        "@timestamp": now(),
        "event": {"kind": "event", "category": ["network"], "type": ["info"],
                  "dataset": "ct.monitor"},
        "message": f"New certificate in CT logs for {domain} issued by {issuer_name}",
        "x509": {
            "issuer": {"distinguished_name": issuer.get("name")},
            "not_before": row.get("not_before"),
            "not_after": row.get("not_after"),
            "alternative_names": row.get("dns_names", []),
        },
        "ct": {
            "monitored_domain": domain,
            "issuance_id": row.get("id"),
            "issuer": issuer_name,
            "tbs_sha256": row.get("tbs_sha256"),
            "cert_sha256": row.get("cert_sha256"),
            "baseline": baseline,
            "issuer_unexpected": unexpected,
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("domain")
    ap.add_argument("--allowed-issuers", default=os.environ.get("CT_ALLOWED_ISSUERS", ""),
                    help="regex of expected issuers, e.g. \"Let's Encrypt|Google Trust\"")
    ap.add_argument("--state-dir", default="/var/lib/ct-monitor")
    ap.add_argument("--out", default="/var/log/ct-monitor/ct.ndjson")
    ap.add_argument("--skip-baseline", action="store_true",
                    help="record existing certs as seen without emitting events")
    args = ap.parse_args()

    domain = args.domain.lower().strip(".")
    state_dir, out = Path(args.state_dir), Path(args.out)
    state_dir.mkdir(parents=True, exist_ok=True)
    out.parent.mkdir(parents=True, exist_ok=True)

    lock = open(state_dir / f"{domain}.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("already running", file=sys.stderr)
        return 0

    state_path = state_dir / f"{domain}.json"
    state = load_state(state_path)
    baseline = state["cursor"] is None
    seen = set(state["seen"])
    token = os.environ.get("CERTSPOTTER_TOKEN")
    new = 0

    with out.open("a") as fh:
        while True:
            page = fetch(domain, state["cursor"], token)
            print("page: " + str(page))
            input()
            if not page:
                break
            for row in page:
                tbs = row.get("tbs_sha256")
                print("tbs: " + str(tbs))
                if not tbs or tbs in seen:
                    print("continue")
                    continue
                print("add tbs")
                seen.add(tbs)
                input()
                if baseline and args.skip_baseline:
                    print("baseline? " + str(baseline))
                    input()
                    continue
                fh.write(json.dumps(build_event(domain, row, baseline,
                                                args.allowed_issuers)) + "\n")
                new += 1
            fh.flush()
            os.fsync(fh.fileno())
            # write output first, then state: a crash gives duplicates, never misses
            state["cursor"] = page[-1]["id"]
            state["seen"] = sorted(seen)
            save_state(state_path, state)

    print(f"{now()} domain={domain} new={new} baseline={baseline}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except urllib.error.URLError as e:
        print(f"ct-monitor: request failed: {e}", file=sys.stderr)
        sys.exit(1)

