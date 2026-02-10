param(
  [Parameter(Position=0)]
  [string]$Command = "up",
  [string[]]$Only
)

$ErrorActionPreference = "Stop"
$script:TargetLabel = ""

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptRoot "..")
$ConfigPath = Join-Path $RepoRoot "config\conduit.json"
$DashboardDir = Join-Path $RepoRoot "dashboard"

function Write-Info($msg) {
  if ($script:TargetLabel) {
    Write-Host "[conduit][$script:TargetLabel] $msg"
  } else {
    Write-Host "[conduit] $msg"
  }
}

function Set-Target($name) {
  $script:TargetLabel = $name
}

function Get-TargetLabel($vps) {
  $name = if ($vps.name) { $vps.name } else { $vps.host }
  if ($vps.host -and $name -and $vps.host -ne $name) {
    return "$name [$($vps.host)]"
  }
  return $name
}

function Load-Config {
  if (!(Test-Path $ConfigPath)) {
    throw "Missing config file: $ConfigPath"
  }
  $raw = Get-Content $ConfigPath -Raw
  return $raw | ConvertFrom-Json
}

function Normalize-OnlyTargets($Only) {
  if (-not $Only) { return @() }
  $targets = @()
  foreach ($item in $Only) {
    if (-not $item) { continue }
    $parts = $item -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $targets += $parts
  }
  return $targets
}

function Filter-VpsList($list, $targets) {
  if (-not $targets -or $targets.Count -eq 0) { return $list }
  return $list | Where-Object {
    $name = if ($_.name) { $_.name } else { $null }
    $vpsHost = $_.host
    $targets -contains $name -or $targets -contains $vpsHost
  }
}

function Save-HostKey($cfg, $hostkey) {
  if (-not $hostkey -or -not (Test-Path $ConfigPath)) { return }
  try {
    $raw = Get-Content $ConfigPath -Raw | ConvertFrom-Json
  } catch {
    return
  }
  if (-not $raw.vps) { return }
  $updated = $false
  foreach ($item in $raw.vps) {
    $matchesHost = $item.host -and $cfg.host -and $item.host -eq $cfg.host
    $matchesName = $item.name -and $cfg.name -and $item.name -eq $cfg.name
    if ($matchesHost -or $matchesName) {
      if (-not $item.hostkey) {
        $item | Add-Member -NotePropertyName hostkey -NotePropertyValue $hostkey -Force
        $updated = $true
      }
    }
  }
  if ($updated) {
    $jsonOut = $raw | ConvertTo-Json -Depth 10
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($ConfigPath, $jsonOut, $utf8NoBom)
    Write-Info "Saved hostkey to config for $($cfg.host)"
  }
}

function Merge-Config([hashtable]$base, $override) {
  $result = @{}
  foreach ($key in $base.Keys) { $result[$key] = $base[$key] }
  foreach ($prop in $override.PSObject.Properties) {
    $result[$prop.Name] = $prop.Value
  }
  return [pscustomobject]$result
}

function Get-VpsList($cfg) {
  $defaults = @{}
  foreach ($prop in $cfg.PSObject.Properties) {
    if ($prop.Name -in @("vps", "defaults")) { continue }
    $defaults[$prop.Name] = $prop.Value
  }
  if ($cfg.defaults) {
    foreach ($prop in $cfg.defaults.PSObject.Properties) {
      $defaults[$prop.Name] = $prop.Value
    }
  }
  if ($cfg.vps) {
    $list = @()
    $idx = 1
    foreach ($item in $cfg.vps) {
      $merged = Merge-Config $defaults $item
      if (-not $merged.name) {
        $fallback = if ($merged.host) { $merged.host } else { "vps-$idx" }
        $merged | Add-Member -NotePropertyName name -NotePropertyValue $fallback
      }
      $list += $merged
      $idx++
    }
    return $list
  }
  $single = Merge-Config $defaults $cfg
  if (-not $single.name) {
    $fallback = if ($single.host) { $single.host } else { "vps-1" }
    $single | Add-Member -NotePropertyName name -NotePropertyValue $fallback
  }
  return @($single)
}

function Assert-Config($cfg) {
  if (-not $cfg.host -or $cfg.host -eq "YOUR_VPS_IP") {
    throw "Set config host in $ConfigPath"
  }
  if (-not $cfg.user) { throw "Set config user in $ConfigPath" }
  if (-not $cfg.ssh_key_path) { throw "Set ssh_key_path in $ConfigPath" }
}

function Ensure-SshKey($cfg) {
  $keyPath = $cfg.ssh_key_path
  $keyDir = Split-Path -Parent $keyPath
  if (!(Test-Path $keyDir)) {
    New-Item -ItemType Directory -Force -Path $keyDir | Out-Null
  }
  if (!(Test-Path $keyPath)) {
    Write-Info "Generating SSH key at $keyPath"
    & ssh-keygen -t ed25519 -f $keyPath --% -N "" | Out-Null
  }
}

function Get-PlinkPath {
  $plink = Get-Command plink -ErrorAction SilentlyContinue
  if ($plink) { return $plink.Source }
  foreach ($path in @("C:\Program Files\PuTTY\plink.exe", "C:\Program Files (x86)\PuTTY\plink.exe")) {
    if (Test-Path $path) { return $path }
  }
  return $null
}

function Get-HostKeyFromPlink($cfg) {
  $plinkPath = Get-PlinkPath
  if (-not $plinkPath) { return $null }
  if (-not $cfg.host -or -not $cfg.user) { return $null }
  $port = if ($cfg.ssh_port) { $cfg.ssh_port } else { 22 }
  $userAtHost = "$($cfg.user)@$($cfg.host)"
  $cmd = "`"$plinkPath`" -batch -ssh -P $port -v $userAtHost exit 2>&1"
  $output = (& cmd /c $cmd | Out-String)
  if ($env:CONDUIT_DEBUG_HOSTKEY -eq "1") {
    Write-Info ("Hostkey probe output length: {0}" -f $output.Length)
  }
  $lines = $output -split "`r?`n"
  $pattern = "(ssh-[A-Za-z0-9-]+)\s+(\d+)\s+(SHA256:[A-Za-z0-9+/=]+)"
  if ($env:CONDUIT_DEBUG_HOSTKEY -eq "1") {
    Write-Info ("Hostkey regex: {0}" -f $pattern)
  }
  foreach ($line in $lines) {
    if ($line -match $pattern) {
      if ($env:CONDUIT_DEBUG_HOSTKEY -eq "1") {
        Write-Info "Hostkey match success: True"
      }
      return "$($Matches[1]) $($Matches[2]) $($Matches[3])"
    }
  }
  if ($env:CONDUIT_DEBUG_HOSTKEY -eq "1") {
    Write-Info "Hostkey match success: False"
    $line = ($lines | Where-Object { $_ -match "^ssh-" } | Select-Object -First 1)
    if ($line) { Write-Info ("Hostkey probe line: {0}" -f $line) }
    if ($line) {
      $bytes = [System.Text.Encoding]::UTF8.GetBytes($line)
      Write-Info ("Hostkey probe bytes: {0}" -f ($bytes -join "," ))
    }
  }
  return $null
}

function Get-HostKeyFromSshKeyscan($cfg) {
  if (-not $cfg.host) { return $null }
  $port = if ($cfg.ssh_port) { $cfg.ssh_port } else { 22 }
  $tempKey = New-TemporaryFile
  try {
    $scanCmd = "ssh-keyscan -p $port $($cfg.host) 2>nul"
    & cmd /c $scanCmd | Out-File -FilePath $tempKey -Encoding ascii
    if (-not (Test-Path $tempKey) -or (Get-Item $tempKey).Length -eq 0) { return $null }
    $line = & ssh-keygen -lf $tempKey 2>$null | Select-Object -First 1
    if (-not $line) { return $null }
    $parts = $line -split "\s+"
    if ($parts.Count -lt 3) { return $null }
    $bits = $parts[0]
    $fp = $parts[1]
    $typeRaw = $parts[-1].Trim("()").ToUpperInvariant()
    $type = switch ($typeRaw) {
      "ED25519" { "ssh-ed25519" }
      "RSA" { "ssh-rsa" }
      "ECDSA" { "ecdsa-sha2-nistp256" }
      default { $null }
    }
    if (-not $type) { return $null }
    return "$type $bits $fp"
  } finally {
    Remove-Item $tempKey -Force -ErrorAction SilentlyContinue
  }
}

function Install-SshKey($cfg) {
  $pub = "$($cfg.ssh_key_path).pub"
  if (!(Test-Path $pub)) {
    throw "Missing public key: $pub"
  }
  $plinkPath = Get-PlinkPath
  $cmd = "umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys"
  if ($cfg.password -and $plinkPath) {
    if (-not $cfg.hostkey) {
      $detected = Get-HostKeyFromPlink $cfg
      if (-not $detected) {
        $detected = Get-HostKeyFromSshKeyscan $cfg
      }
      if ($detected) {
        Write-Info "Auto-detected hostkey: $detected"
        $cfg | Add-Member -NotePropertyName hostkey -NotePropertyValue $detected -Force
        Save-HostKey $cfg $detected
      }
    }
    if ($cfg.hostkey) {
      Write-Info "Installing SSH key on server (using plink with password from config)."
      Get-Content $pub | & $plinkPath -batch -ssh -P $cfg.ssh_port -pw $cfg.password `
        -hostkey $cfg.hostkey "$($cfg.user)@$($cfg.host)" $cmd
      if ($LASTEXITCODE -ne 0) {
        throw "Failed to install SSH key via plink (exit code $LASTEXITCODE). Check password/host key."
      }
      return
    }
    throw "Unable to auto-detect hostkey for $($cfg.host). Install PuTTY/ssh-keyscan or add hostkey to config."
  }
  {
    Write-Info "Installing SSH key on server (you may be prompted for the root password)."
    Get-Content $pub | & ssh -p $cfg.ssh_port -o StrictHostKeyChecking=accept-new `
      -o PreferredAuthentications=password -o PubkeyAuthentication=no `
      "$($cfg.user)@$($cfg.host)" $cmd
    if ($LASTEXITCODE -ne 0) {
      throw "Failed to install SSH key via ssh (exit code $LASTEXITCODE). Check password."
    }
  }
}

function Test-SshKey($cfg) {
  & ssh -i $cfg.ssh_key_path -p $cfg.ssh_port -o BatchMode=yes `
    -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new `
    "$($cfg.user)@$($cfg.host)" "echo ok" | Out-Null
  return ($LASTEXITCODE -eq 0)
}

function Invoke-Remote($cfg, $scriptText) {
  $temp = New-TemporaryFile
  $normalized = $scriptText -replace "`r`n", "`n"
  [System.IO.File]::WriteAllText($temp, $normalized, [System.Text.Encoding]::ASCII)
  $remotePath = "/tmp/conduit-remote-$([Guid]::NewGuid().ToString('N')).sh"
  $keepRemote = $env:CONDUIT_KEEP_REMOTE -eq "1"
  try {
    & scp -i $cfg.ssh_key_path -P $cfg.ssh_port -o BatchMode=yes `
      -o StrictHostKeyChecking=accept-new $temp "$($cfg.user)@$($cfg.host):$remotePath" | Out-Null
    if ($LASTEXITCODE -ne 0) {
      throw "Failed to upload remote script (exit code $LASTEXITCODE)."
    }
    if ($keepRemote) {
      Write-Info "Remote script saved at $remotePath"
      & ssh -i $cfg.ssh_key_path -p $cfg.ssh_port -o BatchMode=yes `
        -o StrictHostKeyChecking=accept-new "$($cfg.user)@$($cfg.host)" "bash $remotePath"
    } else {
      & ssh -i $cfg.ssh_key_path -p $cfg.ssh_port -o BatchMode=yes `
        -o StrictHostKeyChecking=accept-new "$($cfg.user)@$($cfg.host)" "bash $remotePath; rm -f $remotePath"
    }
    if ($LASTEXITCODE -ne 0) {
      throw "Remote command failed (exit code $LASTEXITCODE)."
    }
  } finally {
    Remove-Item $temp -Force
  }
}

function Ensure-Remote($cfg) {
  $bandwidth = $cfg.bandwidth
  if ($bandwidth -is [string] -and $bandwidth.ToLower() -eq "unlimited") {
    $bandwidth = -1
  }
  $statsFile = $cfg.stats_file
  $geoEnabled = if ($cfg.geo_enabled -eq $true) { "true" } else { "false" }
  $geoPort = if ($cfg.geo_port) { [int]$cfg.geo_port } else { 9101 }
  $geoInterval = if ($cfg.geo_interval_sec) { [int]$cfg.geo_interval_sec } else { 15 }
  $geoWindow = if ($cfg.geo_window_sec) { [int]$cfg.geo_window_sec } else { 300 }
  $geoPorts = @()
  if ($cfg.geo_ports) {
    if ($cfg.geo_ports -is [array]) { $geoPorts = $cfg.geo_ports }
    else { $geoPorts = @($cfg.geo_ports) }
  }
  $geoPortsArg = ""
  if ($geoPorts.Count -gt 0) {
    $geoPortsArg = "--ports " + ($geoPorts -join ",")
  }
  $agentEnabled = if ($cfg.agent_enabled -eq $false) { "false" } else { "true" }
  $agentPort = if ($cfg.agent_port) { [int]$cfg.agent_port } else { 9201 }
  $agentInterval = if ($cfg.agent_interval_sec) { [int]$cfg.agent_interval_sec } else { 15 }
  $desired = @{
    max_clients = [int]$cfg.max_clients
    bandwidth = $bandwidth
    metrics_port = [int]$cfg.metrics_port
    stats_file = $statsFile
  } | ConvertTo-Json -Compress
  $desiredB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($desired))

  $remote = @"
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

desired_b64="$desiredB64"
current_b64=""
state="not_running"
if docker ps --filter name=conduit --format '{{.Status}}' | grep -q '^Up'; then
  state="running"
fi
if [ -f "$($cfg.remote_dir)/desired.json" ]; then
  current_b64=`$(base64 -w0 < "$($cfg.remote_dir)/desired.json")`
fi
conduit_ok="false"
if [ "`$state" = "running" ] && [ "`$current_b64" = "`$desired_b64" ]; then
  echo "[remote] Conduit already running with desired config"
  conduit_ok="true"
fi

if [ "`$conduit_ok" != "true" ]; then
  echo "[remote] Pulling Conduit image"
  docker pull ghcr.io/psiphon-inc/conduit/cli:latest

  echo "[remote] Starting Conduit container"
  docker rm -f conduit >/dev/null 2>&1 || true
  mkdir -p "$($cfg.remote_dir)/data"
  chown -R 1000:999 "$($cfg.remote_dir)/data"
  echo "`$desired_b64" | base64 -d > "$($cfg.remote_dir)/desired.json"
  stats_file="$statsFile"
  stats_arg=""
  if [ -n "`$stats_file" ]; then
    stats_arg="--stats-file `$stats_file"
  fi
  docker run -d --name conduit --restart unless-stopped \
    -v "$($cfg.remote_dir)/data:/data" \
    -p 127.0.0.1:$($cfg.metrics_port):$($cfg.metrics_port) \
    ghcr.io/psiphon-inc/conduit/cli:latest \
    start --data-dir /data --metrics-addr 0.0.0.0:$($cfg.metrics_port) \
    --max-clients $($cfg.max_clients) --bandwidth $bandwidth \
    `$stats_arg $($cfg.extra_args -join " ")
  echo "[remote] Done"
fi

geo_enabled="$geoEnabled"
geo_port="$geoPort"
geo_interval="$geoInterval"
geo_window="$geoWindow"
if [ "`$geo_enabled" = "true" ]; then
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
  mkdir -p "$($cfg.remote_dir)/geo"
  cat > "$($cfg.remote_dir)/geo/geo_tracker.py" <<'PY'
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
  chmod +x "$($cfg.remote_dir)/geo/geo_tracker.py"
  cat > /etc/systemd/system/conduit-geo.service <<EOF
[Unit]
Description=Conduit Geo Tracker
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $($cfg.remote_dir)/geo/geo_tracker.py --port $geoPort --interval $geoInterval --window-sec $geoWindow $geoPortsArg
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now conduit-geo.service
  systemctl restart conduit-geo.service
fi

agent_enabled="$agentEnabled"
agent_port="$agentPort"
agent_interval="$agentInterval"
if [ "`$agent_enabled" = "true" ]; then
  echo "[remote] Setting up metrics agent"
  if ! command -v python3 >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y python3
  fi
  mkdir -p "$($cfg.remote_dir)/agent"
  cat > "$($cfg.remote_dir)/agent/agent.py" <<'PY'
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
  chmod +x "$($cfg.remote_dir)/agent/agent.py"
  cat > /etc/systemd/system/conduit-agent.service <<EOF
[Unit]
Description=Conduit Metrics Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $($cfg.remote_dir)/agent/agent.py --port $agentPort --interval $agentInterval --metrics-url http://127.0.0.1:$($cfg.metrics_port)/metrics --geo-url http://127.0.0.1:$geoPort/geo --db $($cfg.remote_dir)/agent/data.db
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now conduit-agent.service
  systemctl restart conduit-agent.service
fi
"@
  Invoke-Remote $cfg $remote
}

function Show-Status($cfg) {
  Invoke-Remote $cfg "docker ps --filter name=conduit --format '{{.Status}}'"
}

function Show-Logs($cfg) {
  Invoke-Remote $cfg "docker logs --tail 200 conduit"
}

function Quick-Status($cfg) {
  $metricsPort = $cfg.metrics_port
  $cmd = "curl -s http://127.0.0.1:$metricsPort/metrics"
  $raw = & ssh -i $cfg.ssh_key_path -p $cfg.ssh_port -o BatchMode=yes `
    -o StrictHostKeyChecking=accept-new "$($cfg.user)@$($cfg.host)" $cmd
  if ($LASTEXITCODE -ne 0 -or -not $raw) {
    throw "Failed to fetch metrics from server."
  }

  $lines = $raw -split "`n"
  function Get-MetricValue($names) {
    foreach ($name in $names) {
      $pattern = "^\s*$name(?:\{[^}]*\})?\s+([0-9eE\.\+\-]+)"
      $line = ($lines | Where-Object { $_ -match $pattern } | Select-Object -First 1)
      if ($line) {
        $parts = $line -split "\s+"
        return [double]$parts[-1]
      }
    }
    return $null
  }

  function Format-Bytes($n) {
    if ($n -eq $null) { return "--" }
    $units = @("B","KB","MB","GB","TB","PB")
    $i = 0
    $val = [math]::Abs($n)
    while ($val -ge 1024 -and $i -lt $units.Length - 1) { $val /= 1024; $i++ }
    return "{0:N2} {1}" -f ($val * [math]::Sign($n)), $units[$i]
  }

  $clientsVal = Get-MetricValue @("conduit_connected_clients","conduit_clients_connected","conduit_clients")
  $upVal = Get-MetricValue @("conduit_bytes_uploaded","conduit_bytes_sent","conduit_bytes_out")
  $downVal = Get-MetricValue @("conduit_bytes_downloaded","conduit_bytes_received","conduit_bytes_in")

  $prefix = if ($script:TargetLabel) { "[$script:TargetLabel] " } else { "" }
  if ($env:CONDUIT_DEBUG_QUICK -eq "1") {
    $rawLen = if ($raw -is [array]) { $raw.Count } else { $raw.Length }
    Write-Host ("{0}Debug: raw length={1} lines={2}" -f $prefix, $rawLen, $lines.Count)
    $connLine = ($lines | Where-Object { $_ -like "*conduit_connected_clients*" } | Select-Object -First 1)
    if ($connLine) { Write-Host ("{0}Debug: found line: {1}" -f $prefix, $connLine) }
  }
  if (($clientsVal -eq $null -and $upVal -eq $null -and $downVal -eq $null) -and $env:CONDUIT_DEBUG_QUICK -eq "1") {
    Write-Host ("{0}Debug: metrics sample (first 10 lines):" -f $prefix)
    $lines | Select-Object -First 10 | ForEach-Object { Write-Host ("{0}  {1}" -f $prefix, $_) }
  }
  Write-Host ("{0}Clients: {1}" -f $prefix, ($clientsVal -as [int]))
  Write-Host ("{0}Uploaded: {1}" -f $prefix, (Format-Bytes $upVal))
  Write-Host ("{0}Downloaded: {1}" -f $prefix, (Format-Bytes $downVal))

  $countryLines = $lines | Where-Object { $_ -match 'country="' }
  if ($countryLines.Count -eq 0) {
    Write-Host ("{0}Countries: not available in metrics" -f $prefix)
    return
  }
  $totals = @{}
  foreach ($line in $countryLines) {
    if ($line -match 'country="([^"]+)"') {
      $country = $Matches[1]
      $value = Parse-Value $line
      if ($value -ne $null) {
        if (-not $totals.ContainsKey($country)) { $totals[$country] = 0.0 }
        $totals[$country] += $value
      }
    }
  }
  $top = $totals.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
  Write-Host ("{0}Top countries:" -f $prefix)
  foreach ($row in $top) {
    Write-Host ("  {0}{1}: {2}" -f $prefix, $row.Key, (Format-Bytes $row.Value))
  }
}

function Wait-LocalPort($port, $timeoutSec) {
  $deadline = [DateTime]::UtcNow.AddSeconds($timeoutSec)
  while ([DateTime]::UtcNow -lt $deadline) {
    try {
      $client = New-Object System.Net.Sockets.TcpClient
      $iar = $client.BeginConnect("127.0.0.1", $port, $null, $null)
      if ($iar.AsyncWaitHandle.WaitOne(300)) {
        $client.EndConnect($iar)
        $client.Close()
        return $true
      }
      $client.Close()
    } catch {
      # ignore
    }
    Start-Sleep -Milliseconds 300
  }
  return $false
}

function Ensure-LocalPortAvailable($port, $purpose) {
  try {
    $connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
  } catch {
    $connections = @()
  }
  foreach ($conn in $connections) {
    $proc = $null
    try {
      $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    } catch {
      $proc = $null
    }
    if ($proc -and $proc.ProcessName -eq "ssh") {
      Write-Info "Stopping existing SSH tunnel on local port $port ($purpose)"
      Stop-Process -Id $proc.Id -Force
      Start-Sleep -Milliseconds 200
      continue
    }
    if ($proc) {
      throw "Local port $port is already in use by $($proc.ProcessName) (PID $($proc.Id)). Stop it and retry."
    }
    throw "Local port $port is already in use. Stop the process and retry."
  }
}

function Start-Dashboard($cfgRaw) {
  $vpsList = Get-VpsList $cfgRaw
  $dashboardPort = 8080
  $metricsBase = 19090
  $geoBase = 19101
  $agentBase = 19201
  $tunnels = @()
  $dashVps = @()
  $idx = 0
  $usedPorts = New-Object System.Collections.Generic.HashSet[int]

  foreach ($vps in $vpsList) {
    $idx++
    $vpsName = if ($vps.name) { $vps.name } else { $vps.host }
    Set-Target (Get-TargetLabel $vps)
    Assert-Config $vps
    Ensure-SshKey $vps

    $localMetrics = if ($vps.local_metrics_port) { [int]$vps.local_metrics_port } else { $metricsBase + $idx - 1 }
    while ($usedPorts.Contains($localMetrics)) { $localMetrics++ }
    $usedPorts.Add($localMetrics) | Out-Null

    $geoEnabled = $vps.geo_enabled -eq $true
    $agentEnabled = $vps.agent_enabled -ne $false
    $localGeo = $null
    if ($geoEnabled) {
      $localGeo = if ($vps.local_geo_port) { [int]$vps.local_geo_port } else { $geoBase + $idx - 1 }
      while ($usedPorts.Contains($localGeo)) { $localGeo++ }
      $usedPorts.Add($localGeo) | Out-Null
    }
    $localAgent = $null
    if ($agentEnabled) {
      $localAgent = if ($vps.local_agent_port) { [int]$vps.local_agent_port } else { $agentBase + $idx - 1 }
      while ($usedPorts.Contains($localAgent)) { $localAgent++ }
      $usedPorts.Add($localAgent) | Out-Null
    }

    $sshLog = Join-Path $env:TEMP "conduit-ssh-$localMetrics.log"
    $remoteMetrics = if ($vps.metrics_port) { [int]$vps.metrics_port } else { 9090 }
    $remoteGeo = if ($vps.geo_port) { [int]$vps.geo_port } else { 9101 }
    Ensure-LocalPortAvailable $localMetrics "metrics"
    Write-Info "Starting SSH tunnel for metrics on local port $localMetrics"
    $tunnel = Start-Process -FilePath "ssh" -ArgumentList @(
      "-i", $vps.ssh_key_path,
      "-p", $vps.ssh_port,
      "-o", "ExitOnForwardFailure=yes",
      "-o", "ServerAliveInterval=30",
      "-o", "ServerAliveCountMax=3",
      "-N",
      "-L", "${localMetrics}:127.0.0.1:$remoteMetrics",
      "$($vps.user)@$($vps.host)"
    ) -PassThru -NoNewWindow -RedirectStandardError $sshLog
    $tunnels += $tunnel

    if (-not (Wait-LocalPort $localMetrics 8)) {
      if ($tunnel -and !$tunnel.HasExited) { $tunnel | Stop-Process -Force }
      $err = ""
      if (Test-Path $sshLog) { $err = (Get-Content $sshLog -Raw).Trim() }
      throw "SSH tunnel failed to start on localhost:$localMetrics. $err"
    }
    if ($tunnel.HasExited) {
      $err = ""
      if (Test-Path $sshLog) { $err = (Get-Content $sshLog -Raw).Trim() }
      throw "SSH tunnel exited unexpectedly on localhost:$localMetrics. $err"
    }

    if ($geoEnabled -and $localGeo) {
      $geoLog = Join-Path $env:TEMP "conduit-ssh-$localGeo.log"
      Ensure-LocalPortAvailable $localGeo "geo"
      Write-Info "Starting SSH tunnel for geo stats on local port $localGeo"
      $geoTunnel = Start-Process -FilePath "ssh" -ArgumentList @(
        "-i", $vps.ssh_key_path,
        "-p", $vps.ssh_port,
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
        "-N",
        "-L", "${localGeo}:127.0.0.1:$remoteGeo",
        "$($vps.user)@$($vps.host)"
      ) -PassThru -NoNewWindow -RedirectStandardError $geoLog
      $tunnels += $geoTunnel

      if (-not (Wait-LocalPort $localGeo 8)) {
        if ($geoTunnel -and !$geoTunnel.HasExited) { $geoTunnel | Stop-Process -Force }
        $err = ""
        if (Test-Path $geoLog) { $err = (Get-Content $geoLog -Raw).Trim() }
        throw "SSH tunnel failed to start on localhost:$localGeo. $err"
      }
      if ($geoTunnel.HasExited) {
        $err = ""
        if (Test-Path $geoLog) { $err = (Get-Content $geoLog -Raw).Trim() }
        throw "SSH tunnel exited unexpectedly on localhost:$localGeo. $err"
      }
    }

    if ($agentEnabled -and $localAgent) {
      $remoteAgent = if ($vps.agent_port) { [int]$vps.agent_port } else { 9201 }
      $agentLog = Join-Path $env:TEMP "conduit-ssh-$localAgent.log"
      Ensure-LocalPortAvailable $localAgent "agent"
      Write-Info "Starting SSH tunnel for agent on local port $localAgent"
      $agentTunnel = Start-Process -FilePath "ssh" -ArgumentList @(
        "-i", $vps.ssh_key_path,
        "-p", $vps.ssh_port,
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
        "-N",
        "-L", "${localAgent}:127.0.0.1:$remoteAgent",
        "$($vps.user)@$($vps.host)"
      ) -PassThru -NoNewWindow -RedirectStandardError $agentLog
      $tunnels += $agentTunnel

      if (-not (Wait-LocalPort $localAgent 8)) {
        if ($agentTunnel -and !$agentTunnel.HasExited) { $agentTunnel | Stop-Process -Force }
        $err = ""
        if (Test-Path $agentLog) { $err = (Get-Content $agentLog -Raw).Trim() }
        throw "SSH tunnel failed to start on localhost:$localAgent. $err"
      }
      if ($agentTunnel.HasExited) {
        $err = ""
        if (Test-Path $agentLog) { $err = (Get-Content $agentLog -Raw).Trim() }
        throw "SSH tunnel exited unexpectedly on localhost:$localAgent. $err"
      }
    }

    $dashVps += [pscustomobject]@{
      id = $vpsName
      label = $vpsName
      host = $vps.host
      metrics_url = "http://127.0.0.1:$localMetrics/metrics"
      geo_url = if ($geoEnabled -and $localGeo) { "http://127.0.0.1:$localGeo/geo" } else { "" }
      sys_url = if ($geoEnabled -and $localGeo) { "http://127.0.0.1:$localGeo/sys" } else { "" }
      agent_url = if ($agentEnabled -and $localAgent) { "http://127.0.0.1:$localAgent" } else { "" }
    }
  }

  $dashConfigPath = Join-Path $DashboardDir "config.json"
  $existing = $null
  if (Test-Path $dashConfigPath) {
    try { $existing = Get-Content $dashConfigPath -Raw | ConvertFrom-Json } catch { $existing = $null }
  }
  $pollInterval = if ($cfgRaw.poll_interval_sec) { [int]$cfgRaw.poll_interval_sec } elseif ($existing -and $existing.poll_interval_sec) { [int]$existing.poll_interval_sec } else { 10 }
  $dbPath = if ($existing -and $existing.db_path) { $existing.db_path } else { (Join-Path $DashboardDir "data.db") }
  $dashConfig = [ordered]@{}
  foreach ($key in @("clients_metric","bytes_up_metric","bytes_down_metric","country_metric","country_label")) {
    if ($existing -and $existing.$key) { $dashConfig[$key] = $existing.$key }
  }
  $dashConfig["poll_interval_sec"] = $pollInterval
  $dashConfig["db_path"] = $dbPath
  $dashConfig["vps"] = $dashVps
  $jsonOut = $dashConfig | ConvertTo-Json -Depth 6
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($dashConfigPath, $jsonOut, $utf8NoBom)

  try {
    Set-Target ""
    Write-Info "Starting local dashboard on http://127.0.0.1:$dashboardPort"
    & python (Join-Path $DashboardDir "server.py") --port $dashboardPort --config $dashConfigPath --metrics-url "http://127.0.0.1:0/metrics"
  } finally {
    foreach ($proc in $tunnels) {
      if ($proc -and !$proc.HasExited) { $proc | Stop-Process -Force }
    }
  }
}

switch ($Command) {
  "init" {
    Write-Info "Config file: $ConfigPath"
  }
  "bootstrap-ssh" {
    $cfgRaw = Load-Config
    $vpsList = Get-VpsList $cfgRaw
    $vpsList = Filter-VpsList $vpsList (Normalize-OnlyTargets $Only)
    foreach ($vps in $vpsList) {
      Set-Target (Get-TargetLabel $vps)
      Assert-Config $vps
      Ensure-SshKey $vps
      Write-Info "Installing SSH key (if missing)"
      Install-SshKey $vps
    }
    Set-Target ""
  }
  "up" {
    $cfgRaw = Load-Config
    $vpsList = Get-VpsList $cfgRaw
    $vpsList = Filter-VpsList $vpsList (Normalize-OnlyTargets $Only)
    foreach ($vps in $vpsList) {
      Set-Target (Get-TargetLabel $vps)
      Assert-Config $vps
      Ensure-SshKey $vps
      Write-Info "Checking SSH connectivity"
      if (-not (Test-SshKey $vps)) {
        Write-Info "SSH key not installed. Installing now."
        Install-SshKey $vps
      } else {
        Write-Info "SSH key already installed."
      }
      Write-Info "Provisioning remote services (Docker, Conduit, geo, agent)"
      Ensure-Remote $vps
      Write-Info "Checking Conduit container status"
      Show-Status $vps
      Write-Info "Conduit deployed."
    }
    Set-Target ""
  }
  "status" {
    $cfgRaw = Load-Config
    $vpsList = Get-VpsList $cfgRaw
    $vpsList = Filter-VpsList $vpsList (Normalize-OnlyTargets $Only)
    foreach ($vps in $vpsList) {
      Set-Target (Get-TargetLabel $vps)
      Assert-Config $vps
      Show-Status $vps
    }
    Set-Target ""
  }
  "logs" {
    $cfgRaw = Load-Config
    $vpsList = Get-VpsList $cfgRaw
    $vpsList = Filter-VpsList $vpsList (Normalize-OnlyTargets $Only)
    foreach ($vps in $vpsList) {
      Set-Target (Get-TargetLabel $vps)
      Assert-Config $vps
      Show-Logs $vps
    }
    Set-Target ""
  }
  "quick" {
    $cfgRaw = Load-Config
    $vpsList = Get-VpsList $cfgRaw
    $vpsList = Filter-VpsList $vpsList (Normalize-OnlyTargets $Only)
    foreach ($vps in $vpsList) {
      Set-Target (Get-TargetLabel $vps)
      Assert-Config $vps
      Quick-Status $vps
    }
    Set-Target ""
  }
  "dashboard" {
    $cfgRaw = Load-Config
    Start-Dashboard $cfgRaw
  }
  default {
    throw "Unknown command: $Command"
  }
}
