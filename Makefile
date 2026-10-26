.PHONY: test lint

test:
	python3 -m unittest discover -s tests -v

lint:
	python3 -m py_compile ct_monitor.py
	bash -n install.sh
	python3 -c "import json; json.load(open('elastic/component-template.json'))"
	@command -v systemd-analyze >/dev/null && systemd-analyze verify systemd/ct-monitor@.service systemd/ct-monitor@.timer || true
