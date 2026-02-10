set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

echo "[remote] Checking Docker..."

if ! command -v docker >/dev/null 2>&1; then
  echo "[remote] Installing Docker + Compose (first run can take several minutes)"
  apt-get update -y
  apt-get install -y docker.io
  systemctl enable --now docker
fi

desired_b64="eyJiYW5kd2lkdGgiOi0xLCJtYXhfY2xpZW50cyI6NTAwLCJtZXRyaWNzX3BvcnQiOjkwOTAsInN0YXRzX2ZpbGUiOiIvZGF0YS9zdGF0cy5qc29uIn0="
current_b64=""
state="not_running"
if docker ps --filter name=conduit --format '{{.Status}}' | grep -q '^Up'; then
  state="running"
fi
if [ -f "/opt/conduit/desired.json" ]; then
  current_b64=$(base64 -w0 < "/opt/conduit/desired.json")
fi
conduit_ok="false"
if [ "$state" = "running" ] && [ "$current_b64" = "$desired_b64" ]; then
  echo "[remote] Conduit already running with desired config"
  conduit_ok="true"
fi

if [ "$conduit_ok" != "true" ]; then
  echo "[remote] Pulling Conduit image"
  docker pull ghcr.io/psiphon-inc/conduit/cli:latest

  echo "[remote] Starting Conduit container"
  docker rm -f conduit >/dev/null 2>&1 || true
  mkdir -p "/opt/conduit/data"
  chown -R 1000:999 "/opt/conduit/data"
  echo "$desired_b64" | base64 -d > "/opt/conduit/desired.json"
  stats_file="/data/stats.json"
  stats_arg=""
  if [ -n "$stats_file" ]; then
    stats_arg="--stats-file $stats_file"
  fi
  docker run -d --name conduit --restart unless-stopped \
    -v "/opt/conduit/data:/data" \
    -p 127.0.0.1:9090:9090 \
    ghcr.io/psiphon-inc/conduit/cli:latest \
    start --data-dir /data --metrics-addr 0.0.0.0:9090 \
    --max-clients 500 --bandwidth -1 \
    $stats_arg 
  echo "[remote] Done"
fi

geo_enabled="true"
geo_port="9101"
geo_interval="15"
if [ "$geo_enabled" = "true" ]; then
  echo "[remote] Setting up geo tracker"
  if ! command -v conntrack >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y conntrack
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y python3
  fi
  if ! command -v geoiplookup >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y geoip-bin geoip-database || true
  fi
  mkdir -p "/opt/conduit/geo"
  cat > "/opt/conduit/geo/geo_tracker.py" <<'PY'
#!/usr/bin/env python3
import argparse
import ipaddress
import json
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"timestamp": 0, "countries": [], "total": 0, "error": None}
LOCK = threading.Lock()
CACHE = {}

def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

def load_local_ips():
    try:
        out = subprocess.check_output(["ip", "-4", "-o", "addr", "show", "scope", "global"], text=True)
    except Exception:
        return set()
    ips = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            addr = parts[3].split("/")[0]
            ips.add(addr)
    return ips

def geoip_lookup(ip):
    if ip in CACHE:
        return CACHE[ip]
    country = "ZZ"
    try:
        out = subprocess.check_output(["geoiplookup", ip], text=True, stderr=subprocess.DEVNULL)
        if ":" in out:
            country = out.split(":", 1)[1].strip().split(",")[0]
    except Exception:
        country = "ZZ"
    CACHE[ip] = country
    return country

def collect(local_ips):
    try:
        out = subprocess.check_output(["conntrack", "-L"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return set()
    ips = set()
    for line in out.splitlines():
        if "src=" not in line or "dst=" not in line:
            continue
        src = dst = sport = dport = None
        for token in line.split():
            if token.startswith("src="):
                src = token[4:]
            elif token.startswith("dst="):
                dst = token[4:]
            elif token.startswith("sport="):
                sport = token[6:]
            elif token.startswith("dport="):
                dport = token[6:]
        if sport == "22" or dport == "22":
            continue
        if src and src in local_ips and dst:
            remote = dst
        elif dst and dst in local_ips and src:
            remote = src
        else:
            remote = src or dst
        if remote and is_public(remote):
            ips.add(remote)
    return ips

def update_loop(interval):
    while True:
        try:
            local_ips = load_local_ips()
            remote_ips = collect(local_ips)
            totals = {}
            for ip in remote_ips:
                country = geoip_lookup(ip)
                totals[country] = totals.get(country, 0) + 1
            rows = [{"country": k, "clients": v} for k, v in totals.items()]
            rows.sort(key=lambda r: r["clients"], reverse=True)
            with LOCK:
                STATE["timestamp"] = int(time.time())
                STATE["countries"] = rows[:50]
                STATE["total"] = sum(totals.values())
                STATE["error"] = None
        except Exception as exc:
            with LOCK:
                STATE["error"] = str(exc)
        time.sleep(interval)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/geo"):
            with LOCK:
                payload = dict(STATE)
            data = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(404)
        self.end_headers()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9101)
    parser.add_argument("--interval", type=int, default=15)
    args = parser.parse_args()
    thread = threading.Thread(target=update_loop, args=(args.interval,), daemon=True)
    thread.start()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.serve_forever()

if __name__ == "__main__":
    main()
PY
  chmod +x "/opt/conduit/geo/geo_tracker.py"
  cat > /etc/systemd/system/conduit-geo.service <<EOF
[Unit]
Description=Conduit Geo Tracker
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/conduit/geo/geo_tracker.py --port 9101 --interval 15
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now conduit-geo.service
fi
