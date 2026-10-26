#!/usr/bin/env bash
# Install (or uninstall) ct-monitor on a systemd host. Run from the repo root as root.
#   sudo ./install.sh               install
#   sudo ./install.sh --uninstall   remove program and units (keeps state, logs, env file)
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root (sudo ./install.sh)" >&2; exit 1; }
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ "${1:-}" == "--uninstall" ]]; then
  systemctl list-units --plain --no-legend 'ct-monitor@*.timer' 2>/dev/null \
    | awk '{print $1}' | xargs -r systemctl disable --now
  rm -f /usr/local/bin/ct-monitor \
        /etc/systemd/system/ct-monitor@.service /etc/systemd/system/ct-monitor@.timer \
        /etc/logrotate.d/ct-monitor
  rm -rf /usr/local/share/doc/ct-monitor
  systemctl daemon-reload
  echo "Removed. State (/var/lib/ct-monitor), logs (/var/log/ct-monitor) and /etc/ct-monitor were kept."
  exit 0
fi

command -v python3 >/dev/null || { echo "python3 is required (apt install python3)" >&2; exit 1; }
python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' \
  || { echo "python3 >= 3.8 required" >&2; exit 1; }

install -D -m 0755 ct_monitor.py                   /usr/local/bin/ct-monitor
install -D -m 0644 systemd/ct-monitor@.service     /etc/systemd/system/ct-monitor@.service
install -D -m 0644 systemd/ct-monitor@.timer       /etc/systemd/system/ct-monitor@.timer
install -D -m 0644 logrotate/ct-monitor            /etc/logrotate.d/ct-monitor
install -D -m 0644 README.md                       /usr/local/share/doc/ct-monitor/README.md

install -d -m 0755 /etc/ct-monitor
if [[ ! -e /etc/ct-monitor/ct-monitor.env ]]; then
  install -m 0640 config/ct-monitor.env.example /etc/ct-monitor/ct-monitor.env
  echo "Created /etc/ct-monitor/ct-monitor.env (edit it to set your allowed issuers / API token)"
fi

systemctl daemon-reload
cat <<'EOF'

Installed. Next:
  1. Try it without side effects:   ct-monitor example.com --dry-run
  2. Enable the hourly timer:       sudo systemctl enable --now ct-monitor@example.com.timer
  3. Run it once right now:         sudo systemctl start ct-monitor@example.com.service
  4. Configure Elastic (README.md, "Configure Elastic").
EOF
