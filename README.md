# CT Monitor → Elastic Stack Setup Guide

## 1. Architecture

The data flow is:

```text
ct-monitor.py <DOMAIN>
        |
        | Collects Certificate Transparency data
        v
  JSON log file (NDJSON)
        |
        v
  Elastic Agent
  Custom Logs (Filestream) integration
        |
        v
  Elasticsearch data stream
  logs-ct.monitor-default
        |
        v
  Kibana / Discover
```

A systemd timer starts the collection script once per hour. Elastic Agent continuously monitors the configured log file and forwards new events to Elasticsearch.

**Important:** The collection script and Elastic Agent perform separate jobs. The script retrieves and writes the data; Elastic Agent reads the resulting log file and ships the events.

## 2. Prepare the collection script

The script is installed at:

```text
/usr/local/bin/ct-monitor.py
```

It accepts a domain as a positional argument:

```bash
/usr/local/bin/ct-monitor.py example.com
```

Replace `example.com` with the domain you want to monitor.

Check that the script exists and can execute:

```bash
ls -l /usr/local/bin/ct-monitor.py
/usr/local/bin/ct-monitor.py example.com
```

Confirm where the script writes its output. For the configuration below, assume it writes one complete JSON object per line to:

```text
/var/log/ct-monitor/ct-monitor.ndjson
```

If the script already writes to a different file, use that actual path instead. Do not configure two competing output destinations without a reason.

Create the log directory if needed:

```bash
sudo install -d -m 0755 /var/log/ct-monitor
```

The output should be **NDJSON** (newline-delimited JSON): one JSON object per line, not one large JSON array. For example:

```json
{"@timestamp":"2026-10-25T20:46:51.049Z","ct":{"cert_sha256":"example-hash","issuance_id":"13436037477"}}
{"@timestamp":"2026-10-25T20:47:12.000Z","ct":{"cert_sha256":"another-hash","issuance_id":"13436056897"}}
```

These are illustrative examples, not actual certificate records.

## 3. Create a systemd service

Create `/etc/systemd/system/ct-monitor.service`:

```ini
[Unit]
Description=CT Monitor data collection
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ct-monitor.py example.com
```

Replace `example.com` with the actual domain.

The service runs as root by default because no `User=` is specified. If the script does not need root privileges, use a dedicated service account and grant it only the permissions required.

If the script writes to a log file itself, no additional output redirection is required. If it instead writes JSON events to standard output, you can direct stdout to the file being monitored by Elastic Agent:

```ini
StandardOutput=append:/var/log/ct-monitor/ct-monitor.ndjson
StandardError=journal
```

Add those two lines under `[Service]` only if the script emits the desired NDJSON records to stdout. If it already writes the file, do not add this redirection.

## 4. Create a systemd hourly timer

Create `/etc/systemd/system/ct-monitor.timer`:

```ini
[Unit]
Description=Run CT Monitor once per hour

[Timer]
OnCalendar=hourly
Persistent=true
Unit=ct-monitor.service

[Install]
WantedBy=timers.target
```

Explanation:

- `OnCalendar=hourly` schedules hourly runs.
- `Persistent=true` allows a missed scheduled run to be triggered after the machine returns from downtime.
- `Unit=ct-monitor.service` tells systemd which service to start.

Reload systemd and enable the timer:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ct-monitor.timer
```

The timer starts the service; you do not need to enable the service itself.

### Test the service

Run a collection manually:

```bash
sudo systemctl start ct-monitor.service
```

Check its status and logs:

```bash
systemctl status ct-monitor.service
journalctl -u ct-monitor.service -n 100 --no-pager
```

Check the schedule:

```bash
systemctl list-timers ct-monitor.timer
```

A `oneshot` service may show `inactive (dead)` after it completes successfully. That is normal. The timer should remain enabled and waiting for the next run.

## 5. Configure Elastic Agent in Fleet

In Kibana:

1. Open **Management → Fleet → Agents**.
2. Select the Elastic Agent that runs on the CT Monitor host.
3. Open its assigned agent policy.
4. Add the **Custom Logs (Filestream)** integration.
5. Configure the integration to monitor the log file.

Suggested configuration:

| Setting | Value |
|---|---|
| Integration | Custom Logs (Filestream) |
| Dataset | `ct.monitor` |
| Log file path | `/var/log/ct-monitor/ct-monitor.ndjson` |
| Parser | NDJSON / JSON parser |
| JSON target | Root level, if supported by the integration configuration |

The exact labels for the parser options may vary by Elastic integration version. Configure the JSON parser so that each JSON object's fields become individual Elasticsearch fields rather than leaving the entire object as a string in `message`.

Save the integration and wait for Fleet to apply the updated policy.

**Important:** The configured file path must match the actual file produced by the script. Elastic Agent must also have permission to read it.

## 6. Verify ingestion

### A. Verify the file on the Linux host

```bash
sudo ls -lh /var/log/ct-monitor/
sudo tail -n 5 /var/log/ct-monitor/ct-monitor.ndjson
```

Confirm that new records appear after a collection run and that each record is valid JSON on a separate line.

### B. Verify the Elastic Agent

In Kibana → Fleet → Agents, confirm the agent is healthy and that its assigned policy contains the Custom Logs integration.

On the host, inspect the agent logs if ingestion fails. The agent's installation and logging paths depend on how Elastic Agent was installed.

### C. Verify documents in Elasticsearch

Open Kibana → Dev Tools and run:

```json
GET logs-ct.monitor-default/_count
```

Inspect recent events:

```json
GET logs-ct.monitor-default/_search
{
  "size": 10,
  "sort": [
    {
      "@timestamp": "desc"
    }
  ],
  "_source": [
    "@timestamp",
    "message",
    "event.dataset",
    "ct.cert_sha256",
    "ct.issuance_id"
  ]
}
```

Expected dataset:

```text
ct.monitor
```

Expected data stream:

```text
logs-ct.monitor-default
```

If the parser is working correctly, fields such as `ct.cert_sha256` and `ct.issuance_id` should be searchable individually. They should not exist only inside a JSON-formatted `message` string.

## 7. Troubleshooting checklist

| Symptom | What to check |
|---|---|
| Timer fails to start | Confirm both unit files exist under `/etc/systemd/system/`, then run `systemctl daemon-reload`. |
| Script fails | Run it manually with the actual domain and inspect `journalctl -u ct-monitor.service`. |
| No log file appears | Check the script's output configuration and the configured output path. |
| File updates but Elasticsearch receives nothing | Check the integration path, Agent health, file permissions, and Agent logs. |
| Documents arrive with only `message` | Verify the NDJSON parser is configured correctly in the integration. |
| Fields are missing or mapped incorrectly | Inspect a raw event, the JSON structure, and the field mappings. |
| Duplicate events appear | Check whether the script rewrites the file, rotates logs unexpectedly, or emits the same records on every run. |

## 8. Operational notes

- Keep the data stream and Fleet integration intact when changing ingestion configuration.
- Do not schedule a recurring `_delete_by_query` against the entire data stream; it would delete newly collected events as well.
- Use Elasticsearch ILM for retention management rather than periodically deleting the whole data stream.
- If the script collects overlapping historical data each hour, consider deduplicating records or tracking a collection watermark.
- Back up important data and configuration before making destructive Elasticsearch changes.

### Final configuration summary

| Component | Configuration |
|---|---|
| Collector | `/usr/local/bin/ct-monitor.py <DOMAIN>` |
| systemd service | `/etc/systemd/system/ct-monitor.service` |
| systemd timer | `/etc/systemd/system/ct-monitor.timer` |
| Schedule | Hourly |
| Elastic integration | Custom Logs (Filestream) |
| Dataset | `ct.monitor` |
| Data stream | `logs-ct.monitor-default` |
| Parser | NDJSON / JSON |
