# Conduit VPS Bootstrap

![Image](https://github.com/user-attachments/assets/1737d9dc-5cbc-470f-afbf-0a65329f2dc5)

![Image](https://github.com/user-attachments/assets/791ab4af-15ab-4350-85bb-feb0aeb1a3c3)

Deploy Psiphon Conduit to one or more VPSs (via Docker) and run a local dashboard that reads metrics over SSH tunnels.

## Prerequisites (local machine)
- Windows + PowerShell, or macOS/Linux + Bash
- OpenSSH client (`ssh`, `scp`)
- `curl`
- `jq` (required for `scripts/conduit.sh`)
- Python 3 (for the local dashboard)
- Optional (Windows): PuTTY `plink` for non-interactive password auth
- Optional (macOS/Linux): `sshpass` for non-interactive password auth

## Step 1 - Configuration

1. Copy the example config (this repo does **not** include `config\conduit.json` because it is gitignored):

Windows:
```powershell
Copy-Item config\conduit.example.json config\conduit.json
```

macOS/Linux:
```bash
cp config/conduit.example.json config/conduit.json
```

2. Open `config\conduit.json` and replace **every placeholder value** you see in the example:
- `YOUR_SSH_KEY_PATH` -> your local SSH key path. Examples:
  Windows: `C:/Users/YOUR_USERNAME/.ssh/conduit_ed25519`
  macOS: `/Users/YOUR_USERNAME/.ssh/conduit_ed25519`
  Linux: `/home/YOUR_USERNAME/.ssh/conduit_ed25519`
- `YOUR_VPS_1_IP` -> the IP/hostname of your first VPS.
- `YOUR_VPS_1_PASSWORD` -> the SSH password for that VPS user.
- `root` -> your SSH username (if different).
- `22` -> your SSH port (if different).
- `500` -> your desired `max_clients`.
- `-1` -> your desired `bandwidth` limit (`-1` = unlimited).
- `/data/stats.json` -> optional stats file location (or leave as-is).
- `geo_window_sec` -> optional rolling window (seconds) for geo tracker counts (default `300`).
- `geo_ports` -> optional port filter for the geo tracker. Leave empty (`[]`) to include all ports.

## Step 2 - Deploy
Run the deploy command:

Windows:
```powershell
scripts\conduit.ps1 up
```

macOS/Linux (first time):
```bash
chmod +x scripts/conduit.sh
```

macOS/Linux (deploy):
```bash
./scripts/conduit.sh up
```
What `up` does (for each VPS, in order):
- checks SSH key presence and installs it if missing
- verifies SSH connectivity
- installs Docker if missing
- pulls and starts the Conduit container
- installs/starts the geo tracker and metrics agent (if enabled)
- prints per-VPS status after provisioning

## Step 3 - Dashboard
Start the dashboard:

Windows:
```powershell
scripts\conduit.ps1 dashboard
```

macOS/Linux:
```bash
./scripts/conduit.sh dashboard
```
Then open `http://127.0.0.1:8080` in your browser.

## Adding More VPSs
To add a second VPS, append another object to the `vps` array in `config\conduit.json`:
```json
{
  "name": "vps-2",
  "host": "YOUR_VPS_2_IP",
  "password": "YOUR_VPS_2_PASSWORD"
}
```
Then run the Deployment command for the VPS to be set up.

Notes:
- **You do not need to set `hostkey`.** The `up` command auto-detects the host key (when PuTTY `plink` is installed) and saves it into `config\conduit.json`.
- If `plink` is not installed, you will be prompted for the password once so the SSH key can be installed.

## Commands (and what they do)
Windows commands:
- `scripts\conduit.ps1 up`  
  Provision all VPSs: SSH key setup, Docker install, Conduit container, geo tracker, metrics agent, status output.
- `scripts\conduit.ps1 status`  
  Shows the Conduit container status on each VPS.
- `scripts\conduit.ps1 logs`  
  Tail the last 200 lines of the Conduit container logs for each VPS.
- `scripts\conduit.ps1 quick`  
  Quick metrics snapshot (clients/bytes) pulled directly from each VPS.
- `scripts\conduit.ps1 dashboard`  
  Starts local SSH tunnels + dashboard server and regenerates `dashboard\config.json`.

Target a specific VPS (Windows only):
- `scripts\conduit.ps1 up -Only vps-1`  
  Runs `up` only for the named VPS.
- `scripts\conduit.ps1 up -Only vps-1,vps-3`  
  Runs `up` only for the listed VPS names.
- `scripts\conduit.ps1 status -Only 200.x.x.x`  
  You can also target by IP/host.

macOS/Linux commands:
- `./scripts/conduit.sh up`  
  Same as Windows `up`.
- `./scripts/conduit.sh status`  
  Same as Windows `status`.
- `./scripts/conduit.sh logs`  
  Same as Windows `logs`.
- `./scripts/conduit.sh quick`  
  Same as Windows `quick`.
- `./scripts/conduit.sh dashboard`  
  Same as Windows `dashboard`.

Target a specific VPS (macOS/Linux):
- `./scripts/conduit.sh up --only vps-1`  
  Runs `up` only for the named VPS.
- `./scripts/conduit.sh up --only vps-1,vps-3`  
  Runs `up` only for the listed VPS names.
- `./scripts/conduit.sh status --only 200.x.x.x`  
  You can also target by IP/host.

## Notes
- `config\conduit.json` is **gitignored**. Share only `config\conduit.example.json`.
- `dashboard\config.json` is generated automatically when you run `dashboard`.
- Metrics are bound to `127.0.0.1` on the VPS and accessed via SSH tunnels.
- A lightweight metrics agent runs on each VPS and stores history locally.
- On macOS/Linux, if `sshpass` is not installed, SSH key installation will prompt for the VPS password.
- The "Active Remote IPs by Country" chart is derived from network peers observed by the geo tracker. It is **not** a direct count of connected clients and can differ significantly from `conduit_connected_clients`.
