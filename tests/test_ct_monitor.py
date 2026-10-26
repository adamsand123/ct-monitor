import json
import re
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import ct_monitor as ct  # noqa: E402


def row(i, tbs=None, issuer="Let's Encrypt", names=None):
    return {
        "id": str(i),
        "tbs_sha256": tbs or f"tbs{i}",
        "cert_sha256": f"cert{i}",
        "dns_names": names or [f"h{i}.example.com"],
        "not_before": "2026-10-01T00:00:00-00:00",
        "not_after": "2027-01-01T00:00:00-00:00",
        "issuer": {"friendly_name": issuer, "name": f"C=US, O={issuer}, CN=R3"},
    }


class FakeAPI:
    """Serves rows in id order, honouring `after`, 2 per page."""

    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def __call__(self, api_url, domain, after, token, **kw):
        self.calls.append(after)
        start = 0
        if after is not None:
            start = next(i for i, r in enumerate(self.rows) if r["id"] == str(after)) + 1
        return self.rows[start:start + 2]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "state"
        self.out = Path(self.tmp.name) / "log" / "ct.ndjson"

    def run_once(self, api, **kw):
        kw.setdefault("allowed_re", None)
        with mock.patch.object(ct, "fetch_page", api):
            return ct.run_domain("example.com", api_url="x", token=None,
                                 state_dir=self.state, out=self.out, **kw)

    def docs(self):
        if not self.out.exists():
            return []
        return [json.loads(line) for line in self.out.read_text().splitlines()]


class DedupeTests(Base):
    def test_baseline_then_nothing_new(self):
        api = FakeAPI([row(1), row(2), row(3)])
        self.assertEqual(self.run_once(api), 3)
        docs = self.docs()
        self.assertTrue(all(d["ct"]["baseline"] for d in docs))
        self.assertEqual(self.run_once(api), 0)
        self.assertEqual(len(self.docs()), 3)

    def test_new_cert_after_baseline_is_not_baseline(self):
        rows = [row(1), row(2)]
        self.run_once(FakeAPI(rows))
        rows.append(row(3))
        self.assertEqual(self.run_once(FakeAPI(rows)), 1)
        last = self.docs()[-1]
        self.assertFalse(last["ct"]["baseline"])
        self.assertEqual(last["event"]["id"], "3")

    def test_precert_and_cert_share_tbs_and_count_once(self):
        api = FakeAPI([row(1, tbs="same"), row(2, tbs="same"), row(3)])
        self.assertEqual(self.run_once(api), 2)

    def test_lost_cursor_does_not_reemit(self):
        api = FakeAPI([row(1), row(2), row(3)])
        self.run_once(api)
        p = self.state / "example.com.json"
        st = json.loads(p.read_text())
        st["cursor"] = None
        p.write_text(json.dumps(st))
        self.assertEqual(self.run_once(api), 0)

    def test_skip_baseline_emits_nothing_but_records(self):
        rows = [row(1), row(2)]
        self.assertEqual(self.run_once(FakeAPI(rows), skip_baseline=True), 0)
        self.assertEqual(self.docs(), [])
        rows.append(row(3))
        self.assertEqual(self.run_once(FakeAPI(rows), skip_baseline=True), 1)
        self.assertFalse(self.docs()[0]["ct"]["baseline"])

    def test_max_pages_keeps_baseline_flag_until_complete(self):
        rows = [row(i) for i in range(1, 7)]
        self.assertEqual(self.run_once(FakeAPI(rows), max_pages=1), 2)
        self.assertEqual(self.run_once(FakeAPI(rows), max_pages=1), 2)
        self.assertEqual(self.run_once(FakeAPI(rows), max_pages=10), 2)
        self.assertTrue(all(d["ct"]["baseline"] for d in self.docs()))
        rows.append(row(7))
        self.assertEqual(self.run_once(FakeAPI(rows)), 1)
        self.assertFalse(self.docs()[-1]["ct"]["baseline"])


class EventTests(Base):
    def test_issuer_allowlist(self):
        allowed = re.compile("Let's Encrypt", re.I)
        api = FakeAPI([row(1), row(2, issuer="Sketchy CA")])
        self.run_once(api, allowed_re=allowed)
        flags = {d["ct"]["issuer"]: d["ct"]["issuer_unexpected"] for d in self.docs()}
        self.assertEqual(flags, {"Let's Encrypt": False, "Sketchy CA": True})

    def test_no_allowlist_omits_flag(self):
        self.run_once(FakeAPI([row(1)]))
        self.assertNotIn("issuer_unexpected", self.docs()[0]["ct"])

    def test_timestamps_normalised(self):
        self.run_once(FakeAPI([row(1)]))
        srv = self.docs()[0]["tls"]["server"]
        self.assertEqual(srv["x509"]["not_before"], "2026-10-01T00:00:00Z")
        self.assertEqual(srv["not_after"], "2027-01-01T00:00:00Z")

    def test_ecs_shape(self):
        self.run_once(FakeAPI([row(1, names=["a.example.com", "b.example.com"])]))
        d = self.docs()[0]
        self.assertNotIn("x509", d)                      # not a top-level ECS field set
        self.assertEqual(d["event"]["id"], "1")
        self.assertEqual(d["event"]["action"], "certificate-issued")
        self.assertEqual(d["tls"]["server"]["hash"]["sha256"], "CERT1")
        self.assertEqual(d["tls"]["server"]["x509"]["alternative_names"],
                         ["a.example.com", "b.example.com"])
        self.assertEqual(d["related"]["hosts"], ["a.example.com", "b.example.com", "example.com"])
        self.assertEqual(d["related"]["hash"], ["CERT1"])
        self.assertEqual(d["tls"]["server"]["x509"]["issuer"]["organization"], ["Let's Encrypt"])
        self.assertEqual(d["tls"]["server"]["x509"]["issuer"]["common_name"], ["R3"])
        self.assertNotIn("issuance_id", d["ct"])

    def test_dry_run_writes_nothing(self):
        self.assertEqual(self.run_once(FakeAPI([row(1)]), dry_run=True), 1)
        self.assertFalse(self.out.exists())
        self.assertFalse(self.state.exists())


class DnTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(
            ct.parse_dn("C=SE, O=Telia Company AB, CN=Telia RSA OV CA v4"),
            {"country": ["SE"], "organization": ["Telia Company AB"],
             "common_name": ["Telia RSA OV CA v4"]})

    def test_escaped_comma_and_junk(self):
        self.assertEqual(ct.parse_dn("O=Acme\\, Inc, CN=X, 1.2.3=zz"),
                         {"organization": ["Acme, Inc"], "common_name": ["X"]})
        self.assertEqual(ct.parse_dn(None), {})


class DomainTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(ct.normalize_domain("*.Example.COM."), "example.com")
        self.assertEqual(ct.normalize_domain("bücher.example"), "xn--bcher-kva.example")

    def test_invalid(self):
        for bad in ["../etc/passwd", "a/b.com", "localhost", "exa mple.com", "", "-x.com"]:
            with self.assertRaises(ValueError, msg=bad):
                ct.normalize_domain(bad)


class HttpTests(unittest.TestCase):
    """fetch_page against a real local HTTP server."""

    def test_after_param_and_retry_on_429(self):
        seen = []
        state = {"n": 0}

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                seen.append((q, self.headers.get("Authorization")))
                state["n"] += 1
                if state["n"] == 1:
                    self.send_response(429)
                    self.send_header("Retry-After", "1")
                    self.end_headers()
                    return
                body = json.dumps([row(5)]).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        with mock.patch.object(ct, "_sleep") as slept:
            page = ct.fetch_page(f"http://127.0.0.1:{srv.server_port}/v1/issuances",
                                 "example.com", "4", "tok")
        self.assertEqual(page[0]["id"], "5")
        slept.assert_called_once_with(1)
        q, auth = seen[-1]
        self.assertEqual(q["after"], ["4"])
        self.assertEqual(q["domain"], ["example.com"])
        self.assertEqual(q["expand"], ["dns_names", "issuer"])
        self.assertEqual(auth, "Bearer tok")


if __name__ == "__main__":
    unittest.main()
