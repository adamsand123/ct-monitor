# ct-monitor

Watch Certificate Transparency (CT) logs for certificates issued for your domains, and ship **only the ones you haven't seen before** into Elastic as ECS-style events. Use it to catch unexpected issuance: a CA you don't use, a subdomain you didn't create, a certificate someone else requested.

```
 Cert Spotter API ──► ct-monitor (systemd timer, hourly) ──► /var/log/ct-monitor/ct.ndjson
                          │                                         │
                  state: cursor + seen set                  Elastic Agent (Filestream)
                                                                    │
                                                          logs-ct.monitor-default
                                                                    │
                                                         Security detection rules
```

- Pure Python 3 standard library. No pip packages.
- One run checks one or more domains, subdomains included (`include_subdomains`).
- Safe to run repeatedly: a cursor plus a seen-set of TBS hashes means each certificate is reported once.

> **Data source.** crt.sh is not used. Certificates come from the [Cert Spotter](https://sslmate.com/certspotter/api) issuances API (`/v1/issuances`). The field names the script reads (`id`, `tbs_sha256`, `cert_sha256`, `dns_names`, `not_before`, `not_after`, `issuer.name`, `issuer.friendly_name`) are from the API documentation as I know it. The unit tests use a local fake server, so **run the [first-run check](#3-run-it) against the real API before relying on it.**

## Contents

1. [How it works](#how-it-works)
2. [Install](#1-install)
3. [Configure](#2-configure)
4. [Run it](#3-run-it)
5. [Schedule it](#4-schedule-it)
6. [Configure Elastic](#5-configure-elastic)
7. [Triage an alert](#6-triage-an-alert)
8. [Troubleshooting](#troubleshooting)
9. [Limitations](#limitations)
10. [Development](#development)

## How it works

Each run, per domain:

1. Load state from `/var/lib/ct-monitor/<domain>.json`: the last Cert Spotter issuance `id` (**cursor**), the set of TBS hashes already reported (**seen set**), and whether the first full pass is done (**baseline**).
2. Ask the API for issuances `after=<cursor>`, page by page, oldest first.
3. Skip anything whose TBS hash is already in the seen set. A certificate and its precertificate share a TBS hash, so you get **one event per certificate, not two**. The seen set also protects you if the cursor is ever lost.
4. Append the new events to the NDJSON file (flushed and `fsync`ed), **then** save the state. A crash can duplicate an event, never lose one.
5. The very first pass (every certificate that already exists) is tagged `ct.baseline: true`, so existing certificates don't trigger alerts. It is repeated until the whole history has been read, even if that takes several runs (`--max-pages`).
6. If you gave an allowed-issuers regex, every event carries `ct.issuer_unexpected: true|false`. **That field is what you alert on.**

Exit codes: `0` ok, `1` network/API/state error (state is kept, next run resumes), `2` bad arguments.

### Example event

```json
{
  "@timestamp": "2026-10-26T20:25:43.392Z",
  "message": "New certificate in CT logs for example.com issued by Sketchy CA",
  "event": {
    "kind": "event", "category": ["network"], "type": ["info"],
    "action": "certificate-issued", "id": "17941393354",
    "provider": "certspotter", "dataset": "ct.monitor"
  },
  "tls": {
    "server": {
      "issuer": "C=SE, O=Telia Company AB, CN=Telia RSA OV CA v4",
      "not_before": "2026-10-23T11:53:59Z",
      "not_after": "2027-04-24T11:53:59Z",
      "hash": { "sha256": "56DDE7B7473B66FE4F9D234BBB33CD42A87E62D0B23AEDFAF45DBCEB0E61D70D" },
      "x509": {
        "alternative_names": ["h5.example.com"],
        "not_before": "2026-10-23T11:53:59Z",
        "not_after": "2027-04-24T11:53:59Z",
        "issuer": {
          "distinguished_name": "C=SE, O=Telia Company AB, CN=Telia RSA OV CA v4",
          "country": ["SE"], "organization": ["Telia Company AB"],
          "common_name": ["Telia RSA OV CA v4"]
        }
      }
    }
  },
  "related": { "hosts": ["example.com", "h5.example.com"], "hash": ["56DDE7B7..."] },
  "ct": {
    "monitored_domain": "example.com", "issuer": "Telia",
    "tbs_sha256": "4d0b509e...", "baseline": false, "issuer_unexpected": true
  }
}
```

(Values from the test suite and a real sample; hashes shortened.) Elastic Agent adds `agent.*`, `host.*` (the collector, not the certificate), `log.*`, `data_stream.*` and `event.ingested`.

### Field mapping (ECS)

| Field | Meaning |
|---|---|
| `tls.server.x509.*` | The certificate, in ECS x509 fields (`alternative_names`, `not_before`, `not_after`, `issuer.distinguished_name`, parsed `issuer.common_name` / `organization` / `country`). ECS does not allow `x509` at the top level; it is reused under `tls.server`, `tls.client` and `file`. |
| `tls.server.issuer`, `.not_before`, `.not_after` | Same data in the flat TLS fields, so TLS-oriented dashboards and rules work. |
| `tls.server.hash.sha256` | SHA-256 of the certificate as Cert Spotter reports it, uppercase as ECS asks. |
| `event.id` | Cert Spotter issuance id. `event.action` is `certificate-issued`, `event.provider` is `certspotter`. |
| `related.hosts`, `related.hash` | Monitored domain plus every SAN, and the certificate hash, for pivoting in Security. |
| `ct.baseline` | `true` for certificates that existed before monitoring started. |
| `ct.issuer_unexpected` | `true` / `false` against your allowlist. **Absent** when no allowlist is configured. |
| `ct.issuer`, `ct.monitored_domain`, `ct.tbs_sha256` | Tool-specific; no ECS equivalent. |

`@timestamp` is when ct-monitor saw the certificate, not when it was issued; the issuance time is `tls.server.not_before`.

## 1. Install

Requirements: a systemd Linux host (written for Ubuntu 26.04; the code needs Python 3.8+), outbound HTTPS to `api.certspotter.com`, and Elastic Agent if you want the Elastic side.

```bash
git clone <your-repo-url> ct-monitor
cd ct-monitor
sudo ./install.sh
```

`install.sh` installs:

| File | Destination |
|---|---|
| `ct_monitor.py` | `/usr/local/bin/ct-monitor` |
| `systemd/ct-monitor@.service`, `@.timer` | `/etc/systemd/system/` |
| `logrotate/ct-monitor` | `/etc/logrotate.d/` |
| `config/ct-monitor.env.example` | `/etc/ct-monitor/ct-monitor.env` (only if absent) |

To remove it: `sudo ./install.sh --uninstall` (keeps state, logs and the env file).

No systemd, or you want to try it first? You can run the script straight from the checkout:

```bash
python3 ct_monitor.py example.com --dry-run
```

## 2. Configure

Edit `/etc/ct-monitor/ct-monitor.env` (read by systemd, so no `export`, no shell expansion):

```ini
# Regex of CAs you expect. Everything else is flagged ct.issuer_unexpected=true
CT_ALLOWED_ISSUERS="Let's Encrypt|Google Trust Services"

# Optional. A free token raises the API rate limit.
CERTSPOTTER_TOKEN=xxxxxxxx
```

| Variable / flag | Meaning | Default |
|---|---|---|
| `CT_ALLOWED_ISSUERS` / `--allowed-issuers` | Regex (case-insensitive) matched against the issuer's friendly name and distinguished name. | unset: `ct.issuer_unexpected` is omitted |
| `CERTSPOTTER_TOKEN` | Cert Spotter API token (sent as a Bearer token). | unset |
| `CT_STATE_DIR` / `--state-dir` | Where cursors and seen sets live. | `/var/lib/ct-monitor` |
| `CT_OUT` / `--out` | NDJSON file Elastic Agent tails. | `/var/log/ct-monitor/ct.ndjson` |
| `--skip-baseline` | First run records existing certificates as seen without emitting events. | off |
| `--max-pages` | API pages per domain per run (about 100 certificates each). | 100 |
| `--dry-run` / `--json` | Print what would be reported, write nothing. | off |

**Picking the allowed-issuers regex.** Run `--dry-run --json` once and look at `ct.issuer` and `tls.server.x509.issuer.distinguished_name` for your real certificates, then write the regex to match those. If you set it too narrow you get noisy `issuer_unexpected` alerts; too broad (for example `.`) and the flag never fires.

**Per-domain settings.** The env file applies to every domain. To override for one domain: `sudo systemctl edit ct-monitor@example.com.service` and add `[Service]` / `Environment="CT_ALLOWED_ISSUERS=..."`.

## 3. Run it

**List what exists, change nothing** (do this first):

```bash
ct-monitor example.com --dry-run
```

One line per certificate: issuance id, `not_before`, issuer, the first SAN names, and whether the issuer is expected. Add `--json` to see the full documents, which is the quickest way to check the field mapping against the real API.

If you see 429 errors on a large domain, set `CERTSPOTTER_TOKEN` or run it again later; progress is saved after every page.

**Real run** (writes state and the NDJSON file; needs write access to those paths, so use sudo or the systemd unit):

```bash
sudo systemctl start ct-monitor@example.com.service
journalctl -u ct-monitor@example.com.service -n 20 --no-pager
tail -n 3 /var/log/ct-monitor/ct.ndjson | python3 -m json.tool
```

The first run reports the existing certificates with `ct.baseline: true`. A second run should say `emitted=0`. Several domains at once also work: `ct-monitor example.com example.org`.

Don't want the baseline documents in Elastic at all? Use `sudo ct-monitor example.com --skip-baseline` for the first run (or add `--skip-baseline` in a drop-in), then enable the timer.

**Forget everything and start over** for a domain: `sudo rm /var/lib/ct-monitor/example.com.json` (the next run is a new baseline).

## 4. Schedule it

systemd timer, one instance per domain. The unit name carries the domain:

```bash
sudo systemctl enable --now ct-monitor@example.com.timer
sudo systemctl enable --now ct-monitor@example.org.timer
systemctl list-timers 'ct-monitor@*'
```

The timer runs hourly with up to 5 minutes of random delay, and `Persistent=true` catches up after downtime. CT data lags issuance by minutes to hours, so running more often than hourly buys little and eats your rate limit. To change the interval: `sudo systemctl edit ct-monitor@example.com.timer` and set `OnCalendar=` (clear it first with an empty `OnCalendar=` line).

The service runs as a transient unprivileged user (`DynamicUser=yes`) with a locked-down sandbox, and only needs outbound HTTPS.

**Without systemd** (cron):

```cron
17 * * * * root CT_ALLOWED_ISSUERS="Let's Encrypt" /usr/local/bin/ct-monitor example.com >> /var/log/ct-monitor/run.log 2>&1
```

## 5. Configure Elastic

This assumes Fleet-managed Elastic Agent on the host that runs ct-monitor, healthy in **Fleet → Agents**. Menu names vary a little between Kibana versions.

### 5.1 (Optional) Field mappings

Without this, Elasticsearch guesses the mappings dynamically, which mostly works. With it, `ct.baseline` and `ct.issuer_unexpected` are booleans and the hashes and issuer fields are keywords from day one (Elasticsearch already maps most ECS-named fields on its own). Do it **before** the first data arrives. In **Kibana → Dev Tools**, paste the contents of [`elastic/component-template.json`](elastic/component-template.json) after:

```
PUT _component_template/logs-ct.monitor@custom
```

Fleet adds a `logs-<dataset>@custom` component template to each integration's index template; this replaces the empty one. If the data stream already exists, roll it over so new mappings apply:

```
POST logs-ct.monitor-default/_rollover
```

### 5.2 Add the Custom Logs (Filestream) integration

1. **Fleet → Agent policies**, open the policy of the agent on this host. (Adding the integration to a shared policy such as *Linux Servers* is fine: hosts without the file simply read nothing. If you prefer isolation, create a dedicated policy and move only this host to it, but remember it then loses the other policy's integrations.)
2. **Add integration**, search for **Custom Logs (Filestream)**, **Add Custom Logs (Filestream)**.
3. Fill in:
   - **Integration name:** `ct-monitor`
   - **Paths:** `/var/log/ct-monitor/ct.ndjson`
   - **Dataset name** (under *Advanced options*): `ct.monitor` (must match `event.dataset` in the documents). This produces the data stream `logs-ct.monitor-default`.
   - **Parsers** (under *Advanced options*), as YAML:
     ```yaml
     - ndjson:
         target: ""
         overwrite_keys: true
         add_error_key: true
     ```
     `target: ""` puts the decoded JSON at the event root, and `overwrite_keys` lets the script's own `@timestamp` and `message` win. Don't set `message_key`: the documents have no `msg` field.
   - **Custom configurations** (under *Advanced options*), as YAML:
     ```yaml
     prospector.scanner.fingerprint.enabled: false
     file_identity.native: ~
     ```
     Filestream identifies files by a fingerprint of their first 1024 bytes and **ignores files smaller than that**. A baseline of one or two certificates is smaller, so nothing is shipped until the file grows. This setting avoids the wait. It is safe here because logrotate renames the file and the script creates a new one.
   - Leave **Include files** empty (or use `ct\.ndjson$`). Those patterns are matched against the *full path*, so `^ct.ndjson$` never matches `/var/log/ct-monitor/ct.ndjson`. **Exclude files** `\.gz$` is fine but unnecessary, since the Paths entry names one file.
4. Save and deploy. Fleet bumps the policy revision, and the agent picks it up within a minute or two.

The agent runs as root, so file permissions are not a concern. The file is created world-readable (`0644`); it only contains public CT data.

### 5.3 Check that data arrives

Run the monitor once (section 3), then:

- **Discover:** create a data view for `logs-ct.monitor-*` (Stack Management → Data Views), time range *Last 24 hours*, query `event.dataset : "ct.monitor"`. You should see your baseline certificates.
- Or from Dev Tools: `GET _cat/indices/.ds-logs-ct.monitor*?v`
- If the data view has no `ct.*` fields, check the parsers setting in 5.2; raw JSON in the `message` field means the ndjson parser did not apply.

### 5.4 Create the detection rules

**Security → Rules → Detection rules (SIEM) → Create new rule → Custom query.**

**Rule 1: certificate from an unexpected CA** (the one that matters)

| Setting | Value |
|---|---|
| Index patterns | `logs-ct.monitor-*` |
| Custom query | `event.dataset : "ct.monitor" and ct.baseline : false and ct.issuer_unexpected : true` |
| Name | `CT: certificate issued by unexpected CA` |
| Severity / risk score | High / 73 |
| Runs every / look-back | 1 hour / 30 minutes (look-back longer than the schedule avoids gaps; duplicates are not created for the same source document) |
| Highlighted fields | `ct.monitored_domain`, `ct.issuer`, `tls.server.x509.alternative_names`, `tls.server.not_before` |
| MITRE ATT&CK (optional) | Resource Development → Obtain Capabilities → Digital Certificates (T1588.004). Check attack.mitre.org that the mapping matches what you mean to detect. |

This rule never matches if `CT_ALLOWED_ISSUERS` is unset, because `ct.issuer_unexpected` is then absent.

**Rule 2: any new certificate** (visibility, lower severity)

| Setting | Value |
|---|---|
| Index patterns | `logs-ct.monitor-*` |
| Custom query | `event.dataset : "ct.monitor" and ct.baseline : false` |
| Name | `CT: new certificate issued for monitored domain` |
| Severity / risk score | Low / 21 |

Rule 2 will also fire for your own renewals. If that is too noisy, drop it, or keep it and use the alerts only for the case file and for correlating with your own change records.

**Rule 3 (optional): the monitor stopped working.** A healthy domain produces documents only when a certificate is issued, so an empty index proves nothing. Watch the timer instead: `systemctl list-timers 'ct-monitor@*'` and `journalctl -u 'ct-monitor@*' -p warning`. If you want this in Elastic, ship the journal with the System integration's journald input or add a heartbeat line to the NDJSON file yourself.

### 5.5 Tune it

- **Known-good exceptions:** from an alert, **Add rule exception**, scoped narrowly, for example `ct.issuer is "Let's Encrypt"` combined with `tls.server.x509.alternative_names is "staging.example.com"`.
- **Alert fatigue after the first week:** adjust `CT_ALLOWED_ISSUERS` rather than adding many exceptions.

## 6. Triage an alert

For `CT: certificate issued by unexpected CA`:

1. **Did you or your team request it?** Check ACME client logs, CA accounts, and the change calendar, comparing `tls.server.x509.alternative_names` with what you expected.
2. **Look at the SANs.** A name you don't recognise under your domain suggests a forgotten or hijacked subdomain, or a dangling DNS record.
3. **Check the issuer against your CAA records:** `dig CAA example.com`. A CA that is not listed there should not have issued the certificate and is worth reporting to that CA.
4. **Find the live certificate** if it is deployed: `openssl s_client -connect host:443 -servername host </dev/null | openssl x509 -noout -issuer -dates`.
5. **If it is not legitimate:** request revocation from the issuing CA, rotate anything it could be used to impersonate, and record `tls.server.hash.sha256` and `event.id` in the case.
6. Create a case from the alert (**Take action → Add to new case**) and note the verdict.

## Upgrading from the pre-ECS field names

Versions before 1.1.0 wrote `x509.*`, `ct.issuance_id` and `ct.cert_sha256`. To switch cleanly in a lab (the old documents are not renamed in place):

```
DELETE _data_stream/logs-ct.monitor-default
```

then `sudo rm /var/lib/ct-monitor/*.json`, apply the updated `elastic/component-template.json` (5.1), and run the monitor again. Update any rules or dashboards that used the old names.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `HTTP 429` in the journal | Rate limited. Set `CERTSPOTTER_TOKEN`, or wait. The script retries with `Retry-After`; state is saved per page, so nothing is lost. |
| `invalid domain` (exit 2) | Domain failed validation. Use plain hostnames: `example.com`, not URLs. |
| `PermissionError` writing state or output | You ran it as a normal user. Use `sudo systemctl start ct-monitor@<domain>.service`, or pass `--state-dir`/`--out` paths you own. |
| Every run says `emitted=0` | Normal after the baseline. To re-test, delete `/var/lib/ct-monitor/<domain>.json`. |
| Run reports `reached --max-pages` | Big domain. It continues next run; `ct.baseline` stays `true` until the full history is read. |
| `ct.issuer_unexpected` missing | No allowlist configured. Set `CT_ALLOWED_ISSUERS`. |
| Everything is flagged unexpected | The regex doesn't match your issuer. Check `--dry-run --json` for `ct.issuer` and `tls.server.x509.issuer.distinguished_name`. |
| No documents in Elastic | Check Fleet shows the integration on the agent's policy; `sudo elastic-agent status`; the path in 5.2; that the file is non-empty **and at least 1024 bytes** (or apply the fingerprint setting in 5.2); that *Include files* is empty; and the agent's logs in Fleet (dataset `elastic_agent.filebeat`). |
| JSON stays inside `message` | The ndjson parser wasn't applied (see 5.2). |
| Fields mapped as text or wrong types | Data arrived before the component template existed. Apply 5.1, then `POST logs-ct.monitor-default/_rollover`. |
| Service fails with a status like `226/NAMESPACE` or `218/CAPABILITIES` | A sandbox option your systemd/kernel doesn't support. Remove the hardening lines from `/etc/systemd/system/ct-monitor@.service` one at a time (`systemctl daemon-reload` after each). |

## Limitations

- **Detection after the fact.** CT logs publish after issuance, with a delay of minutes to hours. This tells you a certificate exists; it does not prevent issuance.
- **Depends on one API.** If Cert Spotter changes its API or limits, the script needs adjusting (`fetch_page` and `build_event` are the only places that know the format).
- **Own domains only.** It does not look for lookalike or typosquatted domains.
- **State growth.** The seen set stores one hash per certificate per domain, about 70 bytes each; fine for hundreds of thousands of certificates.
- **Wildcards.** A `*.example.com` certificate shows up as one event; the wildcard appears in `tls.server.x509.alternative_names`.

## Development

```bash
make test    # unit tests (stdlib unittest, includes a local HTTP server test)
make lint    # py_compile, bash -n, JSON check
```

Layout:

```
ct_monitor.py                 the program (installed as /usr/local/bin/ct-monitor)
install.sh                    installer / uninstaller
systemd/                      ct-monitor@.service and ct-monitor@.timer
logrotate/ct-monitor          rotates the NDJSON file
config/ct-monitor.env.example environment file template
elastic/component-template.json   optional field mappings
tests/                        unit tests
```
