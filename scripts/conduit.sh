
#!/usr/bin/env bash
set -euo pipefail

COMMAND="${1:-up}"
shift || true

ONLY_TARGETS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --only|-Only)
      shift || true
      if [[ -n "${1:-}" ]]; then
        IFS=',' read -r -a _parts <<< "$1"
        for part in "${_parts[@]}"; do
          part="$(echo "$part" | xargs)"
          [[ -n "$part" ]] && ONLY_TARGETS+=("$part")
        done
      fi
      ;;
    --only=*)
      value="${1#*=}"
      IFS=',' read -r -a _parts <<< "$value"
      for part in "${_parts[@]}"; do
        part="$(echo "$part" | xargs)"
        [[ -n "$part" ]] && ONLY_TARGETS+=("$part")
      done
      ;;
  esac
  shift || true
done

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_ROOT/.." && pwd)"
CONFIG_PATH="$REPO_ROOT/config/conduit.json"
DASHBOARD_DIR="$REPO_ROOT/dashboard"

TARGET_LABEL=""

write_info() {
  if [[ -n "$TARGET_LABEL" ]]; then
    echo "[conduit][$TARGET_LABEL] $*"
  else
    echo "[conduit] $*"
  fi
}

set_target() {
  TARGET_LABEL="$1"
}

get_target_label() {
  local name="$1"
  local host="$2"
  if [[ -n "$name" && -n "$host" && "$name" != "$host" ]]; then
    echo "$name [$host]"
  else
    echo "${name:-$host}"
  fi
}

die() {
  echo "[conduit] ERROR: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

load_config() {
  [[ -f "$CONFIG_PATH" ]] || die "Missing config file: $CONFIG_PATH"
}

get_vps_list() {
  jq -c '
    def defaults: (del(.vps, .defaults) + (.defaults // {}));
    def ensure_name(idx):
      if .name then . else . + {name: (.host // ("vps-" + ((idx + 1)|tostring)))} end;
    if (.vps | type) == "array" then
      .vps | to_entries | map(.value | (defaults + .) | ensure_name(.key))
    else
      [ (defaults + .) | ensure_name(0) ]
    end
    | .[]
  ' "$CONFIG_PATH"
}

should_include() {
  local name="$1"
  local host="$2"
  if [[ "${#ONLY_TARGETS[@]}" -eq 0 ]]; then
    return 0
  fi
  for t in "${ONLY_TARGETS[@]}"; do
    if [[ "$t" == "$name" || "$t" == "$host" ]]; then
      return 0
    fi
  done
  return 1
}

assert_config() {
  local host="$1"
  local user="$2"
  local ssh_key_path="$3"
  if [[ -z "$host" || "$host" == "YOUR_VPS_IP" || "$host" == "YOUR_VPS_1_IP" ]]; then
    die "Set config host in $CONFIG_PATH"
  fi
  [[ -n "$user" ]] || die "Set config user in $CONFIG_PATH"
  [[ -n "$ssh_key_path" ]] || die "Set ssh_key_path in $CONFIG_PATH"
}

ensure_ssh_key() {
  local key_path="$1"
  local key_dir
  key_dir="$(dirname "$key_path")"
  mkdir -p "$key_dir"
  if [[ ! -f "$key_path" ]]; then
    write_info "Generating SSH key at $key_path"
    ssh-keygen -t ed25519 -f "$key_path" -N "" >/dev/null
  fi
}

verify_hostkey() {
  local host="$1"
  local port="$2"
  local hostkey="$3"
  [[ -n "$hostkey" ]] || return 0
  command -v ssh-keyscan >/dev/null 2>&1 || return 0
  local expected_fp
  expected_fp="$(echo "$hostkey" | awk '{print $3}')"
  [[ -n "$expected_fp" ]] || return 0
  local scanned_fp
  scanned_fp="$(ssh-keyscan -t ed25519 -p "$port" "$host" 2>/dev/null | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')"
  if [[ -n "$scanned_fp" && "$scanned_fp" != "$expected_fp" ]]; then
    die "Host key mismatch for $host. Expected $expected_fp, got $scanned_fp"
  fi
}

install_ssh_key() {
  local host="$1"
  local port="$2"
  local user="$3"
  local ssh_key_path="$4"
  local password="$5"
  local hostkey="$6"
  local pub="${ssh_key_path}.pub"
  [[ -f "$pub" ]] || die "Missing public key: $pub"
  local cmd="umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys"
  verify_hostkey "$host" "$port" "$hostkey"
  if [[ -n "$password" && $(command -v sshpass >/dev/null 2>&1; echo $?) -eq 0 ]]; then
    write_info "Installing SSH key on server (using sshpass with password from config)."
    sshpass -p "$password" ssh -p "$port" -o StrictHostKeyChecking=accept-new \
      -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      "$user@$host" "$cmd" < "$pub"
  else
    write_info "Installing SSH key on server (you may be prompted for the password)."
    ssh -p "$port" -o StrictHostKeyChecking=accept-new \
      -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      "$user@$host" "$cmd" < "$pub"
  fi
}

test_ssh_key() {
  local host="$1"
  local port="$2"
  local user="$3"
  local ssh_key_path="$4"
  ssh -i "$ssh_key_path" -p "$port" -o BatchMode=yes \
    -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new \
    "$user@$host" "echo ok" >/dev/null 2>&1
}
invoke_remote() {
  local host="$1"
  local port="$2"
  local user="$3"
  local ssh_key_path="$4"
  local script_text="$5"
  local tmp
  tmp="$(mktemp)"
  printf "%s\n" "$script_text" > "$tmp"
  local remote_path="/tmp/conduit-remote-$(uuidgen 2>/dev/null || date +%s%N).sh"
  scp -i "$ssh_key_path" -P "$port" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    "$tmp" "$user@$host:$remote_path" >/dev/null
  ssh -i "$ssh_key_path" -p "$port" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    "$user@$host" "bash $remote_path; rm -f $remote_path"
  rm -f "$tmp"
}

ensure_remote() {
  local host="$1"
  local port="$2"
  local user="$3"
  local ssh_key_path="$4"
  local max_clients="$5"
  local bandwidth="$6"
  local metrics_port="$7"
  local stats_file="$8"
  local geo_enabled="$9"
  local geo_port="${10}"
  local geo_interval="${11}"
  local geo_window="${12}"
  local geo_ports="${13}"
  local remote_dir="${14}"
  local extra_args="${15}"
  local agent_enabled="${16}"
  local agent_port="${17}"
  local agent_interval="${18}"

  if [[ "$bandwidth" == "unlimited" ]]; then
    bandwidth="-1"
  fi
  local geo_ports_arg=""
  if [[ -n "$geo_ports" ]]; then
    geo_ports_arg="--ports $geo_ports"
  fi
  local stats_arg=""
  if [[ -n "$stats_file" ]]; then
    stats_arg="--stats-file $stats_file"
  fi
  local desired_json
  desired_json="$(jq -c -n \
    --argjson max_clients "$max_clients" \
    --argjson bandwidth "$bandwidth" \
    --argjson metrics_port "$metrics_port" \
    --arg stats_file "$stats_file" \
    '{max_clients:$max_clients, bandwidth:$bandwidth, metrics_port:$metrics_port, stats_file:$stats_file}')"
  local desired_b64
  desired_b64="$(printf "%s" "$desired_json" | base64 | tr -d '\n')"

  local remote_script
  remote_script="$(cat <<EOF
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

desired_b64="$desired_b64"
current_b64=""
state="not_running"
if docker ps --filter name=conduit --format '{{.Status}}' | grep -q '^Up'; then
  state="running"
fi
if [ -f "$remote_dir/desired.json" ]; then
  current_b64=\$(base64 -w0 < "$remote_dir/desired.json")
fi
conduit_ok="false"
if [ "\$state" = "running" ] && [ "\$current_b64" = "\$desired_b64" ]; then
  echo "[remote] Conduit already running with desired config"
  conduit_ok="true"
fi

if [ "\$conduit_ok" != "true" ]; then
  echo "[remote] Pulling Conduit image"
  docker pull ghcr.io/psiphon-inc/conduit/cli:latest

  echo "[remote] Starting Conduit container"
  docker rm -f conduit >/dev/null 2>&1 || true
  mkdir -p "$remote_dir/data"
  chown -R 1000:999 "$remote_dir/data"
  echo "\$desired_b64" | base64 -d > "$remote_dir/desired.json"
  stats_file="$stats_file"
  stats_arg=""
  if [ -n "\$stats_file" ]; then
    stats_arg="--stats-file \$stats_file"
  fi
  docker run -d --name conduit --restart unless-stopped \
    -v "$remote_dir/data:/data" \
    -p 127.0.0.1:$metrics_port:$metrics_port \
    ghcr.io/psiphon-inc/conduit/cli:latest \
    start --data-dir /data --metrics-addr 0.0.0.0:$metrics_port \
    --max-clients $max_clients --bandwidth $bandwidth \
    \$stats_arg $extra_args
  echo "[remote] Done"
fi

geo_enabled="$geo_enabled"
geo_port="$geo_port"
geo_interval="$geo_interval"
geo_window="$geo_window"
if [ "\$geo_enabled" = "true" ]; then
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
  mkdir -p "$remote_dir/geo"
  cat > "$remote_dir/geo/geo_tracker.py" <<'PY'
#!/usr/bin/env python3
import argparse
import ipaddress
import json
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"timestamp": 0, "countries": [], "total": 0, "error": None, "system": None}
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

def load_container_ips():
    ips = set()
    try:
        out = subprocess.check_output(
            ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "conduit"],
            text=True,
        ).strip()
    except Exception:
        return ips
    for part in out.split():
        if part:
            ips.add(part)
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

def collect(local_ips, container_ips, allowed_ports):
    try:
        out = subprocess.check_output(["conntrack", "-L"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return set()
    ips = set()
    for line in out.splitlines():
        if "src=" not in line or "dst=" not in line:
            continue
        orig_src = orig_dst = orig_sport = orig_dport = None
        reply_src = reply_dst = reply_sport = reply_dport = None
        for token in line.split():
            if token.startswith("src="):
                if orig_src is None:
                    orig_src = token[4:]
                else:
                    reply_src = token[4:]
            elif token.startswith("dst="):
                if orig_dst is None:
                    orig_dst = token[4:]
                else:
                    reply_dst = token[4:]
            elif token.startswith("sport="):
                if orig_sport is None:
                    orig_sport = token[6:]
                else:
                    reply_sport = token[6:]
            elif token.startswith("dport="):
                if orig_dport is None:
                    orig_dport = token[6:]
                else:
                    reply_dport = token[6:]
        def pick_remote(remote, local_port, remote_port):
            if not remote or not is_public(remote):
                return None
            if allowed_ports:
                if (local_port not in allowed_ports) and (remote_port not in allowed_ports):
                    return None
            return remote

        remote = None
        if container_ips:
            if orig_src and orig_src in container_ips and orig_dst:
                remote = pick_remote(orig_dst, orig_sport, orig_dport)
            elif orig_dst and orig_dst in container_ips and orig_src:
                remote = pick_remote(orig_src, orig_dport, orig_sport)
        if remote is None:
            if orig_src and orig_src in local_ips and orig_dst:
                remote = pick_remote(orig_dst, orig_sport, orig_dport)
            elif orig_dst and orig_dst in local_ips and orig_src:
                remote = pick_remote(orig_src, orig_dport, orig_sport)
            elif reply_src and reply_src in local_ips and reply_dst:
                remote = pick_remote(reply_dst, reply_sport, reply_dport)
            elif reply_dst and reply_dst in local_ips and reply_src:
                remote = pick_remote(reply_src, reply_dport, reply_sport)

        if remote:
            ips.add(remote)
    return ips

def read_cpu():
    try:
        with open("/proc/stat", "r", encoding="utf-8") as handle:
            line = handle.readline()
    except Exception:
        return None
    parts = line.split()
    if not parts or parts[0] != "cpu":
        return None
    nums = []
    for value in parts[1:]:
        try:
            nums.append(int(value))
        except ValueError:
            nums.append(0)
    total = sum(nums)
    idle = nums[3] if len(nums) > 3 else 0
    if len(nums) > 4:
        idle += nums[4]
    return total, idle

def read_mem():
    info = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2:
                    key = parts[0].rstrip(":")
                    try:
                        info[key] = int(parts[1])
                    except ValueError:
                        continue
    except Exception:
        return None
    total = info.get("MemTotal")
    available = info.get("MemAvailable", info.get("MemFree"))
    if total is None:
        return None
    if available is None:
        available = 0
    used = max(0, total - available)
    return total * 1024, used * 1024, available * 1024

def read_net():
    rx = 0
    tx = 0
    try:
        with open("/proc/net/dev", "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except Exception:
        return None
    for line in lines[2:]:
        if ":" not in line:
            continue
        iface, data = line.split(":", 1)
        iface = iface.strip()
        if iface == "lo" or iface.startswith("docker") or iface.startswith("veth") or iface.startswith("br-"):
            continue
        fields = data.split()
        if len(fields) >= 16:
            try:
                rx += int(fields[0])
                tx += int(fields[8])
            except ValueError:
                continue
    return rx, tx

def update_loop(interval, allowed_ports, window_sec):
    prev_cpu = None
    prev_net = None
    prev_ts = None
    last_seen = {}
    while True:
        try:
            now = time.time()
            local_ips = load_local_ips()
            container_ips = load_container_ips()
            remote_ips = collect(local_ips, container_ips, allowed_ports)
            for ip in remote_ips:
                last_seen[ip] = now
            cutoff = now - window_sec
            for ip, ts in list(last_seen.items()):
                if ts < cutoff:
                    del last_seen[ip]
            totals = {}
            for ip in last_seen.keys():
                country = geoip_lookup(ip)
                totals[country] = totals.get(country, 0) + 1
            rows = [{"country": k, "clients": v} for k, v in totals.items()]
            rows.sort(key=lambda r: r["clients"], reverse=True)
            cpu = read_cpu()
            cpu_percent = None
            if cpu and prev_cpu:
                total_delta = cpu[0] - prev_cpu[0]
                idle_delta = cpu[1] - prev_cpu[1]
                if total_delta > 0:
                    cpu_percent = (1.0 - (idle_delta / total_delta)) * 100.0
            prev_cpu = cpu
            mem = read_mem()
            mem_total = mem[0] if mem else None
            mem_used = mem[1] if mem else None
            net = read_net()
            net_rx_bps = None
            net_tx_bps = None
            if net and prev_net and prev_ts:
                elapsed = max(0.001, now - prev_ts)
                net_rx_bps = (net[0] - prev_net[0]) / elapsed
                net_tx_bps = (net[1] - prev_net[1]) / elapsed
            prev_net = net
            prev_ts = now
            system = {
                "timestamp": int(now),
                "cpu_percent": cpu_percent,
                "mem_total_bytes": mem_total,
                "mem_used_bytes": mem_used,
                "net_rx_bps": net_rx_bps,
                "net_tx_bps": net_tx_bps,
            }
            with LOCK:
                STATE["timestamp"] = int(time.time())
                STATE["countries"] = rows[:50]
                STATE["total"] = len(last_seen)
                STATE["error"] = None
                STATE["system"] = system
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
        if self.path.startswith("/sys"):
            with LOCK:
                payload = STATE.get("system") or {"error": "no data"}
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
    parser.add_argument("--ports", default="")
    parser.add_argument("--window-sec", type=int, default=300)
    args = parser.parse_args()
    allowed_ports = set()
    if args.ports:
        for part in args.ports.split(","):
            part = part.strip()
            if part.isdigit():
                allowed_ports.add(part)
    window_sec = max(int(args.window_sec), int(args.interval))
    thread = threading.Thread(target=update_loop, args=(args.interval, allowed_ports, window_sec), daemon=True)
    thread.start()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.serve_forever()

if __name__ == "__main__":
    main()
PY
  chmod +x "$remote_dir/geo/geo_tracker.py"
  cat > /etc/systemd/system/conduit-geo.service <<EOF
[Unit]
Description=Conduit Geo Tracker
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $remote_dir/geo/geo_tracker.py --port $geo_port --interval $geo_interval --window-sec $geo_window $geo_ports_arg
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now conduit-geo.service
  systemctl restart conduit-geo.service
fi

agent_enabled="$agent_enabled"
agent_port="$agent_port"
agent_interval="$agent_interval"
if [ "\$agent_enabled" = "true" ]; then
  echo "[remote] Setting up metrics agent"
  if ! command -v python3 >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y python3
  fi
  mkdir -p "$remote_dir/agent"
  cat > "$remote_dir/agent/agent.py" <<'PY'
#!/usr/bin/env python3
import argparse
import json
import os
import re
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from urllib.request import urlopen, Request

METRIC_RE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{.*\})?\s+([-+eE0-9\.]+)$")
LABEL_RE = re.compile(r"(\w+)=" "\"((?:\\.|[^\"])*)\"")

STATE = {"last_fetch": None, "last_error": None}
LOCK = threading.Lock()
MAX_SERIES_POINTS = 600
COUNTRY_TOP_N_DEFAULT = 12
CACHE_LOCK = threading.Lock()
TIMESERIES_CACHE = {}


def parse_labels(raw):
    if not raw:
        return {}
    raw = raw.strip("{}")
    labels = {}
    for match in LABEL_RE.finditer(raw):
        key = match.group(1)
        val = match.group(2).replace("\\\"", "\"")
        labels[key] = val
    return labels


def parse_prometheus(text):
    metrics = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = METRIC_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        labels = parse_labels(m.group(2))
        try:
            value = float(m.group(3))
        except ValueError:
            continue
        metrics.setdefault(name, []).append({"labels": labels, "value": value})
    return metrics


def pick_metric_name(metrics, candidates):
    for candidate in candidates:
        for name in metrics.keys():
            if candidate in name:
                return name
    return ""


def sum_metric(metrics, name):
    if not name or name not in metrics:
        return None
    return sum(sample["value"] for sample in metrics[name])


def init_db(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS samples (
            ts INTEGER PRIMARY KEY,
            clients REAL,
            bytes_up REAL,
            bytes_down REAL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS country_samples (
            ts INTEGER,
            country TEXT,
            value REAL,
            metric TEXT,
            PRIMARY KEY (ts, country, metric)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS totals (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            bytes_up_offset REAL,
            bytes_down_offset REAL,
            last_bytes_up REAL,
            last_bytes_down REAL
        )
        """
    )
    cur.execute(
        """
        INSERT OR IGNORE INTO totals (id, bytes_up_offset, bytes_down_offset, last_bytes_up, last_bytes_down)
        VALUES (1, 0, 0, NULL, NULL)
        """
    )
    conn.commit()
    conn.close()


def store_sample(db_path, ts, clients, bytes_up, bytes_down):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO samples (ts, clients, bytes_up, bytes_down) VALUES (?, ?, ?, ?)",
        (ts, clients, bytes_up, bytes_down),
    )
    conn.commit()
    conn.close()


def update_totals(db_path, bytes_up, bytes_down):
    if bytes_up is None and bytes_down is None:
        return None
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT bytes_up_offset, bytes_down_offset, last_bytes_up, last_bytes_down FROM totals WHERE id = 1")
    row = cur.fetchone()
    if not row:
        bytes_up_offset = 0.0
        bytes_down_offset = 0.0
        last_bytes_up = None
        last_bytes_down = None
        cur.execute(
            "INSERT OR IGNORE INTO totals (id, bytes_up_offset, bytes_down_offset, last_bytes_up, last_bytes_down) VALUES (1, 0, 0, NULL, NULL)"
        )
    else:
        bytes_up_offset, bytes_down_offset, last_bytes_up, last_bytes_down = row
        if last_bytes_up is None and last_bytes_down is None:
            conn.close()
            backfill_totals(db_path)
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT bytes_up_offset, bytes_down_offset, last_bytes_up, last_bytes_down FROM totals WHERE id = 1")
            row = cur.fetchone()
            if row:
                bytes_up_offset, bytes_down_offset, last_bytes_up, last_bytes_down = row

    if bytes_up is not None:
        if last_bytes_up is not None and bytes_up < last_bytes_up:
            bytes_up_offset += last_bytes_up
        last_bytes_up = bytes_up
    if bytes_down is not None:
        if last_bytes_down is not None and bytes_down < last_bytes_down:
            bytes_down_offset += last_bytes_down
        last_bytes_down = bytes_down

    cur.execute(
        "UPDATE totals SET bytes_up_offset = ?, bytes_down_offset = ?, last_bytes_up = ?, last_bytes_down = ? WHERE id = 1",
        (bytes_up_offset, bytes_down_offset, last_bytes_up, last_bytes_down),
    )
    conn.commit()
    conn.close()
    total_up = bytes_up_offset + (bytes_up or 0.0)
    total_down = bytes_down_offset + (bytes_down or 0.0)
    return {"bytes_up": total_up, "bytes_down": total_down}


def load_totals(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT bytes_up_offset, bytes_down_offset, last_bytes_up, last_bytes_down FROM totals WHERE id = 1")
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    bytes_up_offset, bytes_down_offset, last_bytes_up, last_bytes_down = row
    if last_bytes_up is None and last_bytes_down is None:
        return backfill_totals(db_path)
    total_up = bytes_up_offset + (last_bytes_up or 0.0)
    total_down = bytes_down_offset + (last_bytes_down or 0.0)
    return {"bytes_up": total_up, "bytes_down": total_down}


def backfill_totals(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT ts, bytes_up, bytes_down FROM samples ORDER BY ts")
    rows = cur.fetchall()
    bytes_up_offset = 0.0
    bytes_down_offset = 0.0
    last_bytes_up = None
    last_bytes_down = None
    for _, up, down in rows:
        if up is not None:
            if last_bytes_up is not None and up < last_bytes_up:
                bytes_up_offset += last_bytes_up
            last_bytes_up = up
        if down is not None:
            if last_bytes_down is not None and down < last_bytes_down:
                bytes_down_offset += last_bytes_down
            last_bytes_down = down
    cur.execute(
        "UPDATE totals SET bytes_up_offset = ?, bytes_down_offset = ?, last_bytes_up = ?, last_bytes_down = ? WHERE id = 1",
        (bytes_up_offset, bytes_down_offset, last_bytes_up, last_bytes_down),
    )
    conn.commit()
    conn.close()
    if last_bytes_up is None and last_bytes_down is None:
        return None
    total_up = bytes_up_offset + (last_bytes_up or 0.0)
    total_down = bytes_down_offset + (last_bytes_down or 0.0)
    return {"bytes_up": total_up, "bytes_down": total_down}


def store_country_samples(db_path, ts, metric, country_rows):
    if not country_rows:
        return
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.executemany(
        "INSERT OR REPLACE INTO country_samples (ts, country, value, metric) VALUES (?, ?, ?, ?)",
        [(ts, row["country"], row["value"], metric) for row in country_rows],
    )
    conn.commit()
    conn.close()


def parse_range(value):
    if not value or value == "all":
        return None
    if value.endswith("h"):
        return int(value[:-1]) * 3600
    if value.endswith("d"):
        return int(value[:-1]) * 86400
    return None


def compute_bucket(range_sec, interval):
    if not range_sec:
        return max(interval, 3600)
    bucket = int(range_sec / MAX_SERIES_POINTS)
    if bucket < interval:
        bucket = interval
    return max(1, bucket)


def timeseries_cache_ttl(range_value, interval):
    if not range_value or range_value == "all":
        return max(120, interval * 6)
    if range_value.endswith("h"):
        hours = int(range_value[:-1] or 0)
        if hours <= 1:
            return max(10, interval)
        if hours <= 5:
            return max(15, interval * 2)
        return max(60, interval * 6)
    if range_value.endswith("d"):
        days = int(range_value[:-1] or 0)
        if days <= 1:
            return max(30, interval * 3)
        if days <= 7:
            return max(120, interval * 12)
        return max(300, interval * 30)
    return max(60, interval * 6)


def limit_country_series(country_series, limit):
    if not country_series or not limit:
        return country_series
    ranked = []
    for key, rows in country_series.items():
        if not rows:
            continue
        last = rows[-1]
        val = last.get("value") or 0.0
        ranked.append((key, val))
    ranked.sort(key=lambda r: r[1], reverse=True)
    keep = {key for key, _ in ranked[:limit]}
    return {key: rows for key, rows in country_series.items() if key in keep}


def load_series(db_path, range_sec, bucket_sec=None, since_ts=None):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    if since_ts is None and range_sec:
        since_ts = int(time.time()) - range_sec
    if bucket_sec and bucket_sec > 1:
        params = [bucket_sec, bucket_sec]
        where = ""
        if since_ts is not None:
            where = "WHERE ts >= ?"
            params.append(since_ts)
        cur.execute(
            f"""
            SELECT bucket, AVG(clients), MAX(bytes_up), MAX(bytes_down)
            FROM (
                SELECT CAST(ts / ? AS INTEGER) * ? AS bucket, clients, bytes_up, bytes_down
                FROM samples
                {where}
            )
            GROUP BY bucket
            ORDER BY bucket
            """,
            params,
        )
    else:
        if since_ts is not None:
            cur.execute("SELECT ts, clients, bytes_up, bytes_down FROM samples WHERE ts >= ? ORDER BY ts", (since_ts,))
        else:
            cur.execute("SELECT ts, clients, bytes_up, bytes_down FROM samples ORDER BY ts")
    rows = cur.fetchall()
    conn.close()
    return [
        {"ts": ts, "clients": clients, "bytes_up": bytes_up, "bytes_down": bytes_down}
        for ts, clients, bytes_up, bytes_down in rows
    ]


def load_country_series(db_path, range_sec, bucket_sec=None, since_ts=None):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    if since_ts is None and range_sec:
        since_ts = int(time.time()) - range_sec
    if bucket_sec and bucket_sec > 1:
        params = [bucket_sec, bucket_sec]
        where = ""
        if since_ts is not None:
            where = "WHERE ts >= ?"
            params.append(since_ts)
        cur.execute(
            f"""
            SELECT bucket, country, AVG(value), metric
            FROM (
                SELECT CAST(ts / ? AS INTEGER) * ? AS bucket, country, value, metric
                FROM country_samples
                {where}
            )
            GROUP BY bucket, country, metric
            ORDER BY bucket
            """,
            params,
        )
    else:
        if since_ts is not None:
            cur.execute(
                "SELECT ts, country, value, metric FROM country_samples WHERE ts >= ? ORDER BY ts",
                (since_ts,),
            )
        else:
            cur.execute("SELECT ts, country, value, metric FROM country_samples ORDER BY ts")
    rows = cur.fetchall()
    conn.close()
    series = {}
    for ts, country, value, metric in rows:
        key = f"{metric}:{country}"
        series.setdefault(key, []).append({"ts": ts, "value": value, "country": country, "metric": metric})
    return series


def load_latest(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT ts, clients, bytes_up, bytes_down FROM samples ORDER BY ts DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {"ts": row[0], "clients": row[1], "bytes_up": row[2], "bytes_down": row[3]}


def fetch_metrics(url):
    req = Request(url, headers={"User-Agent": "conduit-agent"})
    with urlopen(req, timeout=5) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    return parse_prometheus(text)


def fetch_geo(url):
    if not url:
        return None
    req = Request(url, headers={"User-Agent": "conduit-agent"})
    with urlopen(req, timeout=5) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    return json.loads(text)


def top_countries(geo):
    rows = []
    for row in geo.get("countries", []):
        country = row.get("country")
        value = row.get("clients")
        if country and value is not None:
            rows.append({"country": country, "value": float(value)})
    return rows


def collector_loop(metrics_url, geo_url, db_path, interval):
    while True:
        ts = int(time.time())
        try:
            metrics = fetch_metrics(metrics_url)
            clients_metric = pick_metric_name(metrics, ["connected_clients", "clients_connected", "clients"])
            bytes_up_metric = pick_metric_name(metrics, ["bytes_uploaded", "bytes_sent", "bytes_out"])
            bytes_down_metric = pick_metric_name(metrics, ["bytes_downloaded", "bytes_received", "bytes_in"])
            clients_val = sum_metric(metrics, clients_metric)
            up_val = sum_metric(metrics, bytes_up_metric)
            down_val = sum_metric(metrics, bytes_down_metric)
            store_sample(db_path, ts, clients_val, up_val, down_val)
            totals = update_totals(db_path, up_val, down_val)
            if geo_url:
                geo = fetch_geo(geo_url)
                if geo:
                    store_country_samples(db_path, ts, "geo_active_clients", top_countries(geo))
            with LOCK:
                STATE["last_fetch"] = ts
                STATE["last_error"] = None
                if totals:
                    STATE["totals"] = totals
        except Exception as exc:
            with LOCK:
                STATE["last_error"] = str(exc)
        time.sleep(interval)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/summary"):
            with LOCK:
                last_fetch = STATE["last_fetch"]
                last_error = STATE["last_error"]
                totals = STATE.get("totals")
            latest = load_latest(self.server.db_path)
            if not totals:
                totals = load_totals(self.server.db_path)
            payload = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "last_fetch": last_fetch,
                "status": {
                    "metrics_ok": last_error is None,
                    "last_error": last_error,
                },
                "latest": latest,
                "totals": totals,
            }
            data = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path.startswith("/timeseries"):
            params = parse_qs(urlparse(self.path).query)
            range_value = params.get("range", ["24h"])[0]
            since_raw = params.get("since", [None])[0]
            since_ts = int(since_raw) if since_raw and str(since_raw).isdigit() else None
            range_sec = parse_range(range_value)
            bucket_sec = compute_bucket(range_sec, self.server.interval)
            if since_ts is not None:
                since_ts = since_ts - (since_ts % bucket_sec)
            top_n = self.server.country_top_n
            cache_key = f"{range_value}|{bucket_sec}|{top_n}"
            if since_ts is not None:
                cache_key += f"|since={since_ts}"
            ttl = timeseries_cache_ttl(range_value, self.server.interval)
            with CACHE_LOCK:
                cached = TIMESERIES_CACHE.get(cache_key)
                if cached and (time.time() - cached["ts"] < ttl):
                    data = cached["data"]
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
            series = load_series(self.server.db_path, range_sec, bucket_sec=bucket_sec, since_ts=since_ts)
            country_series = load_country_series(self.server.db_path, range_sec, bucket_sec=bucket_sec, since_ts=since_ts)
            country_series = limit_country_series(country_series, top_n)
            payload = {
                "range": range_value,
                "bucket_sec": bucket_sec,
                "partial": since_ts is not None,
                "series": series,
                "country_series": country_series,
            }
            data = json.dumps(payload).encode("utf-8")
            with CACHE_LOCK:
                TIMESERIES_CACHE[cache_key] = {"ts": time.time(), "data": data}
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
    parser.add_argument("--port", type=int, default=9201)
    parser.add_argument("--interval", type=int, default=15)
    parser.add_argument("--metrics-url", default="http://127.0.0.1:9090/metrics")
    parser.add_argument("--geo-url", default="")
    parser.add_argument("--db", default="/opt/conduit/agent/data.db")
    parser.add_argument("--country-top-n", type=int, default=COUNTRY_TOP_N_DEFAULT)
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.db), exist_ok=True)
    init_db(args.db)
    thread = threading.Thread(
        target=collector_loop, args=(args.metrics_url, args.geo_url, args.db, args.interval), daemon=True
    )
    thread.start()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.db_path = args.db
    server.interval = args.interval
    server.country_top_n = max(1, int(args.country_top_n))
    server.serve_forever()


if __name__ == "__main__":
    main()
PY
  chmod +x "$remote_dir/agent/agent.py"
  cat > /etc/systemd/system/conduit-agent.service <<EOF
[Unit]
Description=Conduit Metrics Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $remote_dir/agent/agent.py --port $agent_port --interval $agent_interval --metrics-url http://127.0.0.1:$metrics_port/metrics --geo-url http://127.0.0.1:$geo_port/geo --db $remote_dir/agent/data.db
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now conduit-agent.service
  systemctl restart conduit-agent.service
fi
EOF
)"

  invoke_remote "$host" "$port" "$user" "$ssh_key_path" "$remote_script"
}
show_status() {
  local host="$1" port="$2" user="$3" ssh_key_path="$4"
  ssh -i "$ssh_key_path" -p "$port" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    "$user@$host" "docker ps --filter name=conduit --format '{{.Status}}'"
}

show_logs() {
  local host="$1" port="$2" user="$3" ssh_key_path="$4"
  ssh -i "$ssh_key_path" -p "$port" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    "$user@$host" "docker logs --tail 200 conduit"
}

format_bytes() {
  local n="$1"
  if [[ -z "$n" ]]; then
    echo "--"
    return
  fi
  awk -v n="$n" 'BEGIN{split("B KB MB GB TB PB",u); i=1; if (n<0){n=-n} while (n>=1024 && i<6){n/=1024; i++} printf "%.2f %s", n, u[i]}'
}

quick_status() {
  local host="$1" port="$2" user="$3" ssh_key_path="$4" metrics_port="$5"
  local raw
  raw="$(ssh -i "$ssh_key_path" -p "$port" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    "$user@$host" "curl -s http://127.0.0.1:$metrics_port/metrics")"
  [[ -n "$raw" ]] || die "Failed to fetch metrics from server."
  local clients up down
  clients="$(echo "$raw" | awk '/^conduit_connected_clients[[:space:]]/{print $2; exit}')"
  up="$(echo "$raw" | awk '/^conduit_bytes_uploaded[[:space:]]/{print $2; exit}')"
  down="$(echo "$raw" | awk '/^conduit_bytes_downloaded[[:space:]]/{print $2; exit}')"
  local prefix=""
  if [[ -n "$TARGET_LABEL" ]]; then
    prefix="[$TARGET_LABEL] "
  fi
  printf "%sClients: %s\n" "$prefix" "${clients:-0}"
  printf "%sUploaded: %s\n" "$prefix" "$(format_bytes "$up")"
  printf "%sDownloaded: %s\n" "$prefix" "$(format_bytes "$down")"
}

wait_local_port() {
  local port="$1"
  local timeout="$2"
  local start
  start="$(date +%s)"
  while true; do
    if command -v nc >/dev/null 2>&1; then
      nc -z 127.0.0.1 "$port" >/dev/null 2>&1 && return 0
    else
      (echo >"/dev/tcp/127.0.0.1/$port") >/dev/null 2>&1 && return 0
    fi
    local now
    now="$(date +%s)"
    if (( now - start >= timeout )); then
      return 1
    fi
    sleep 0.3
  done
}

reserve_port() {
  local port="$1"
  shift
  local used_ports=("$@")
  local candidate="$port"
  local used
  while true; do
    used=0
    for p in "${used_ports[@]}"; do
      if [[ "$p" == "$candidate" ]]; then
        used=1
        break
      fi
    done
    if [[ "$used" -eq 0 ]]; then
      echo "$candidate"
      return
    fi
    candidate=$((candidate + 1))
  done
}
start_dashboard() {
  local poll_interval
  poll_interval="$(jq -r '.poll_interval_sec // empty' "$CONFIG_PATH")"
  local dash_config_path="$DASHBOARD_DIR/config.json"
  local existing_poll=""
  local existing_db=""
  local existing_clients_metric=""
  local existing_bytes_up_metric=""
  local existing_bytes_down_metric=""
  local existing_country_metric=""
  local existing_country_label=""
  if [[ -f "$dash_config_path" ]]; then
    existing_poll="$(jq -r '.poll_interval_sec // empty' "$dash_config_path" 2>/dev/null || true)"
    existing_db="$(jq -r '.db_path // empty' "$dash_config_path" 2>/dev/null || true)"
    existing_clients_metric="$(jq -r '.clients_metric // empty' "$dash_config_path" 2>/dev/null || true)"
    existing_bytes_up_metric="$(jq -r '.bytes_up_metric // empty' "$dash_config_path" 2>/dev/null || true)"
    existing_bytes_down_metric="$(jq -r '.bytes_down_metric // empty' "$dash_config_path" 2>/dev/null || true)"
    existing_country_metric="$(jq -r '.country_metric // empty' "$dash_config_path" 2>/dev/null || true)"
    existing_country_label="$(jq -r '.country_label // empty' "$dash_config_path" 2>/dev/null || true)"
  fi
  if [[ -z "$poll_interval" ]]; then
    poll_interval="$existing_poll"
  fi
  if [[ -z "$poll_interval" ]]; then
    poll_interval="10"
  fi
  local db_path
  db_path="$existing_db"
  if [[ -z "$db_path" ]]; then
    db_path="$DASHBOARD_DIR/data.db"
  fi

  local dashboard_port=8080
  local metrics_base=19090
  local geo_base=19101
  local agent_base=19201
  local used_ports=()
  local tunnels=()
  local dash_vps="[]"
  local idx=0

  while IFS= read -r vps; do
    idx=$((idx + 1))
    local name host user ssh_port ssh_key_path
    name="$(jq -r '.name // empty' <<< "$vps")"
    host="$(jq -r '.host // empty' <<< "$vps")"
    if ! should_include "$name" "$host"; then
      continue
    fi
    user="$(jq -r '.user // empty' <<< "$vps")"
    ssh_port="$(jq -r '.ssh_port // 22' <<< "$vps")"
    ssh_key_path="$(jq -r '.ssh_key_path // empty' <<< "$vps")"
    set_target "$(get_target_label "$name" "$host")"
    assert_config "$host" "$user" "$ssh_key_path"
    ensure_ssh_key "$ssh_key_path"

    local local_metrics local_geo local_agent
    local_metrics="$(jq -r '.local_metrics_port // empty' <<< "$vps")"
    if [[ -z "$local_metrics" ]]; then
      local_metrics="$(reserve_port $((metrics_base + idx - 1)) "${used_ports[@]}")"
    fi
    used_ports+=("$local_metrics")

    local geo_enabled agent_enabled
    geo_enabled="$(jq -r '.geo_enabled // false' <<< "$vps")"
    agent_enabled="$(jq -r '.agent_enabled // true' <<< "$vps")"

    if [[ "$geo_enabled" == "true" ]]; then
      local_geo="$(jq -r '.local_geo_port // empty' <<< "$vps")"
      if [[ -z "$local_geo" ]]; then
        local_geo="$(reserve_port $((geo_base + idx - 1)) "${used_ports[@]}")"
      fi
      used_ports+=("$local_geo")
    fi
    if [[ "$agent_enabled" != "false" ]]; then
      local_agent="$(jq -r '.local_agent_port // empty' <<< "$vps")"
      if [[ -z "$local_agent" ]]; then
        local_agent="$(reserve_port $((agent_base + idx - 1)) "${used_ports[@]}")"
      fi
      used_ports+=("$local_agent")
    fi

    local remote_metrics remote_geo remote_agent
    remote_metrics="$(jq -r '.metrics_port // 9090' <<< "$vps")"
    remote_geo="$(jq -r '.geo_port // 9101' <<< "$vps")"
    remote_agent="$(jq -r '.agent_port // 9201' <<< "$vps")"

    write_info "Starting SSH tunnel for metrics on local port $local_metrics"
    ssh -i "$ssh_key_path" -p "$ssh_port" \
      -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
      -N -L "${local_metrics}:127.0.0.1:${remote_metrics}" "$user@$host" >/dev/null 2>&1 &
    tunnels+=("$!")
    if ! wait_local_port "$local_metrics" 8; then
      die "SSH tunnel failed to start on localhost:$local_metrics"
    fi

    if [[ "$geo_enabled" == "true" && -n "${local_geo:-}" ]]; then
      write_info "Starting SSH tunnel for geo stats on local port $local_geo"
      ssh -i "$ssh_key_path" -p "$ssh_port" \
        -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
        -N -L "${local_geo}:127.0.0.1:${remote_geo}" "$user@$host" >/dev/null 2>&1 &
      tunnels+=("$!")
      if ! wait_local_port "$local_geo" 8; then
        die "SSH tunnel failed to start on localhost:$local_geo"
      fi
    fi

    if [[ "$agent_enabled" != "false" && -n "${local_agent:-}" ]]; then
      write_info "Starting SSH tunnel for agent on local port $local_agent"
      ssh -i "$ssh_key_path" -p "$ssh_port" \
        -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
        -N -L "${local_agent}:127.0.0.1:${remote_agent}" "$user@$host" >/dev/null 2>&1 &
      tunnels+=("$!")
      if ! wait_local_port "$local_agent" 8; then
        die "SSH tunnel failed to start on localhost:$local_agent"
      fi
    fi

    local metrics_url geo_url sys_url agent_url
    metrics_url="http://127.0.0.1:${local_metrics}/metrics"
    geo_url=""
    sys_url=""
    if [[ "$geo_enabled" == "true" && -n "${local_geo:-}" ]]; then
      geo_url="http://127.0.0.1:${local_geo}/geo"
      sys_url="http://127.0.0.1:${local_geo}/sys"
    fi
    agent_url=""
    if [[ "$agent_enabled" != "false" && -n "${local_agent:-}" ]]; then
      agent_url="http://127.0.0.1:${local_agent}"
    fi

    dash_vps="$(jq -c --arg id "$name" --arg label "$name" --arg host "$host" \
      --arg metrics_url "$metrics_url" --arg geo_url "$geo_url" --arg sys_url "$sys_url" --arg agent_url "$agent_url" \
      '. + [{id:$id,label:$label,host:$host,metrics_url:$metrics_url,geo_url:$geo_url,sys_url:$sys_url,agent_url:$agent_url}]' <<< "$dash_vps")"
  done < <(get_vps_list)

  trap 'for pid in "${tunnels[@]}"; do kill "$pid" >/dev/null 2>&1 || true; done' EXIT INT TERM
  local config_out
  config_out="$(jq -n \
    --arg clients_metric "$existing_clients_metric" \
    --arg bytes_up_metric "$existing_bytes_up_metric" \
    --arg bytes_down_metric "$existing_bytes_down_metric" \
    --arg country_metric "$existing_country_metric" \
    --arg country_label "$existing_country_label" \
    --argjson poll_interval "$poll_interval" \
    --arg db_path "$db_path" \
    --argjson vps "$dash_vps" \
    'def opt($v; $k): if $v != "" then {($k): $v} else {} end;
     opt($clients_metric; "clients_metric")
     + opt($bytes_up_metric; "bytes_up_metric")
     + opt($bytes_down_metric; "bytes_down_metric")
     + opt($country_metric; "country_metric")
     + opt($country_label; "country_label")
     + {poll_interval_sec: $poll_interval, db_path: $db_path, vps: $vps}')"
  printf "%s\n" "$config_out" > "$dash_config_path"

  local python_bin="python3"
  if ! command -v "$python_bin" >/dev/null 2>&1; then
    python_bin="python"
  fi
  write_info "Starting local dashboard on http://127.0.0.1:$dashboard_port"
  "$python_bin" "$DASHBOARD_DIR/server.py" --port "$dashboard_port" --config "$dash_config_path" --metrics-url "http://127.0.0.1:0/metrics"
}
case "$COMMAND" in
  init)
    write_info "Config file: $CONFIG_PATH"
    ;;
  bootstrap-ssh)
    load_config
    require_cmd jq
    while IFS= read -r vps; do
      local_name="$(jq -r '.name // empty' <<< "$vps")"
      local_host="$(jq -r '.host // empty' <<< "$vps")"
      if ! should_include "$local_name" "$local_host"; then
        continue
      fi
      local_user="$(jq -r '.user // empty' <<< "$vps")"
      local_port="$(jq -r '.ssh_port // 22' <<< "$vps")"
      local_key="$(jq -r '.ssh_key_path // empty' <<< "$vps")"
      local_password="$(jq -r '.password // empty' <<< "$vps")"
      local_hostkey="$(jq -r '.hostkey // empty' <<< "$vps")"
      set_target "$(get_target_label "$local_name" "$local_host")"
      assert_config "$local_host" "$local_user" "$local_key"
      ensure_ssh_key "$local_key"
      write_info "Installing SSH key (if missing)"
      install_ssh_key "$local_host" "$local_port" "$local_user" "$local_key" "$local_password" "$local_hostkey"
    done < <(get_vps_list)
    set_target ""
    ;;
  up)
    load_config
    require_cmd jq
    while IFS= read -r vps; do
      name="$(jq -r '.name // empty' <<< "$vps")"
      host="$(jq -r '.host // empty' <<< "$vps")"
      if ! should_include "$name" "$host"; then
        continue
      fi
      user="$(jq -r '.user // empty' <<< "$vps")"
      port="$(jq -r '.ssh_port // 22' <<< "$vps")"
      ssh_key_path="$(jq -r '.ssh_key_path // empty' <<< "$vps")"
      password="$(jq -r '.password // empty' <<< "$vps")"
      hostkey="$(jq -r '.hostkey // empty' <<< "$vps")"
      max_clients="$(jq -r '.max_clients // 500' <<< "$vps")"
      bandwidth="$(jq -r '.bandwidth // -1' <<< "$vps")"
      metrics_port="$(jq -r '.metrics_port // 9090' <<< "$vps")"
      geo_enabled="$(jq -r '.geo_enabled // false' <<< "$vps")"
      geo_port="$(jq -r '.geo_port // 9101' <<< "$vps")"
      geo_interval="$(jq -r '.geo_interval_sec // 15' <<< "$vps")"
      geo_window="$(jq -r '.geo_window_sec // 300' <<< "$vps")"
      geo_ports="$(jq -r '.geo_ports | if type=="array" then join(",") else . // "" end' <<< "$vps")"
      remote_dir="$(jq -r '.remote_dir // "/opt/conduit"' <<< "$vps")"
      stats_file="$(jq -r '.stats_file // ""' <<< "$vps")"
      extra_args="$(jq -r '.extra_args | if type=="array" then join(" ") else . // "" end' <<< "$vps")"
      agent_enabled="$(jq -r '.agent_enabled // true' <<< "$vps")"
      agent_port="$(jq -r '.agent_port // 9201' <<< "$vps")"
      agent_interval="$(jq -r '.agent_interval_sec // 15' <<< "$vps")"

      set_target "$(get_target_label "$name" "$host")"
      assert_config "$host" "$user" "$ssh_key_path"
      ensure_ssh_key "$ssh_key_path"
      write_info "Checking SSH connectivity"
      if ! test_ssh_key "$host" "$port" "$user" "$ssh_key_path"; then
        write_info "SSH key not installed. Installing now."
        install_ssh_key "$host" "$port" "$user" "$ssh_key_path" "$password" "$hostkey"
      else
        write_info "SSH key already installed."
      fi
      write_info "Provisioning remote services (Docker, Conduit, geo, agent)"
      ensure_remote "$host" "$port" "$user" "$ssh_key_path" "$max_clients" "$bandwidth" "$metrics_port" "$stats_file" \
        "$geo_enabled" "$geo_port" "$geo_interval" "$geo_window" "$geo_ports" "$remote_dir" "$extra_args" "$agent_enabled" "$agent_port" "$agent_interval"
      write_info "Checking Conduit container status"
      show_status "$host" "$port" "$user" "$ssh_key_path"
      write_info "Conduit deployed."
    done < <(get_vps_list)
    set_target ""
    ;;
  status)
    load_config
    require_cmd jq
    while IFS= read -r vps; do
      name="$(jq -r '.name // empty' <<< "$vps")"
      host="$(jq -r '.host // empty' <<< "$vps")"
      if ! should_include "$name" "$host"; then
        continue
      fi
      user="$(jq -r '.user // empty' <<< "$vps")"
      port="$(jq -r '.ssh_port // 22' <<< "$vps")"
      ssh_key_path="$(jq -r '.ssh_key_path // empty' <<< "$vps")"
      set_target "$(get_target_label "$name" "$host")"
      assert_config "$host" "$user" "$ssh_key_path"
      show_status "$host" "$port" "$user" "$ssh_key_path"
    done < <(get_vps_list)
    set_target ""
    ;;
  logs)
    load_config
    require_cmd jq
    while IFS= read -r vps; do
      name="$(jq -r '.name // empty' <<< "$vps")"
      host="$(jq -r '.host // empty' <<< "$vps")"
      if ! should_include "$name" "$host"; then
        continue
      fi
      user="$(jq -r '.user // empty' <<< "$vps")"
      port="$(jq -r '.ssh_port // 22' <<< "$vps")"
      ssh_key_path="$(jq -r '.ssh_key_path // empty' <<< "$vps")"
      set_target "$(get_target_label "$name" "$host")"
      assert_config "$host" "$user" "$ssh_key_path"
      show_logs "$host" "$port" "$user" "$ssh_key_path"
    done < <(get_vps_list)
    set_target ""
    ;;
  quick)
    load_config
    require_cmd jq
    while IFS= read -r vps; do
      name="$(jq -r '.name // empty' <<< "$vps")"
      host="$(jq -r '.host // empty' <<< "$vps")"
      if ! should_include "$name" "$host"; then
        continue
      fi
      user="$(jq -r '.user // empty' <<< "$vps")"
      port="$(jq -r '.ssh_port // 22' <<< "$vps")"
      ssh_key_path="$(jq -r '.ssh_key_path // empty' <<< "$vps")"
      metrics_port="$(jq -r '.metrics_port // 9090' <<< "$vps")"
      set_target "$(get_target_label "$name" "$host")"
      assert_config "$host" "$user" "$ssh_key_path"
      quick_status "$host" "$port" "$user" "$ssh_key_path" "$metrics_port"
    done < <(get_vps_list)
    set_target ""
    ;;
  dashboard)
    load_config
    require_cmd jq
    start_dashboard
    ;;
  *)
    die "Unknown command: $COMMAND"
    ;;
esac
