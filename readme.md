# Home Lab

Self-hosted services running on a home server, managed as a collection of
independent [Docker Compose](https://docs.docker.com/compose/) stacks — one
folder per service.

## Structure

Each top-level folder is a standalone stack with its own `docker-compose.yml`
(and usually its own `.env` for secrets/config, which is **not** committed —
see [Secrets & data](#secrets--data) below).

```
.
├── changedetection.io/
├── cloudflared/
├── databases/
├── ddns/
├── frigate/
├── immich/
├── influx/
├── jellyfin/
├── label-studio/
├── librenms/
├── metube/
├── mqtt/
├── nebula-sync/
├── nginx/
├── openspeedtest/
├── paperless/
├── radicale/
├── ryott/
├── serr/
├── smokeping/
├── sntp-server/
├── speedtest/
├── syncthing/
├── tubesync/
├── uptime-kuma/
├── vaultwarden/
├── audit_compose.py
└── .gitignore
```

Stacks are independent — start, stop, and update them individually rather
than as one giant Compose project.

## Services

| Service | What it does |
|---|---|
| **changedetection.io** | Monitors web pages for changes and sends alerts |
| **cloudflared** | Cloudflare Tunnel client — exposes internal services without opening inbound ports |
| **databases** | Shared database instance(s) used by other stacks |
| **ddns** | Dynamic DNS updater for a home connection with a changing IP |
| **frigate** | NVR with real-time object detection for local security cameras |
| **immich** | Self-hosted photo and video backup, à la Google Photos |
| **influx** | InfluxDB — time-series database for metrics |
| **jellyfin** | Media server for movies, TV, and music |
| **label-studio** | Data labeling tool for ML/annotation work |
| **librenms** | Network monitoring and device discovery |
| **metube** | Web UI for downloading videos via youtube-dl/yt-dlp |
| **mqtt** | MQTT broker (e.g. Mosquitto) for IoT/home automation messaging |
| **nebula-sync** | *(describe what this does)* |
| **nginx** | Reverse proxy in front of other services |
| **openspeedtest** | Self-hosted internet speed test |
| **paperless** | Document management — scan, OCR, and archive paperwork |
| **radicale** | CalDAV/CardDAV server for calendars and contacts |
| **ryott** | *(describe what this does)* |
| **serr** | *(describe what this does)* |
| **smokeping** | Latency/packet-loss monitoring over time |
| **sntp-server** | Local NTP/time server |
| **speedtest** | Internet speed test (alternate to openspeedtest, or scheduled runs) |
| **syncthing** | Peer-to-peer file synchronization across devices |
| **tubesync** | Automated YouTube channel/playlist downloader |
| **uptime-kuma** | Uptime/status monitoring for all the above |
| **vaultwarden** | Self-hosted Bitwarden-compatible password manager |

Fill in the two placeholders above (`nebula-sync`, `ryott`, `serr`) with a
one-line description of what each one does.

## Getting started

1. Clone the repo onto the host that will run it:
   ```bash
   git clone <this-repo-url>
   cd home-lab
   ```
2. For each stack you want to run, create its `.env` file from a template
   (see below) and fill in real values — hostnames, passwords, API keys, etc.
3. Bring a stack up:
   ```bash
   cd <service>/
   docker compose up -d
   ```
4. Check logs / status:
   ```bash
   docker compose logs -f
   docker compose ps
   ```

## Secrets & data

This repo intentionally does **not** contain:

- `.env` files (actual secrets/config — see `.gitignore`)
- Bind-mounted data directories (`data/`, `appdata/`, `vw-data/`, database
  files, TLS certs, SSH keys, etc.)

Only the `docker-compose.yml` files (and any static, non-secret config) are
version-controlled. Runtime data and credentials live on the host and are
backed up separately (not through GitHub).

If you're setting this up fresh, create an `.env.example` next to each
`docker-compose.yml` with the required variable names and placeholder
values, so the real `.env` can be filled in locally without guessing what's
needed.

## Auditing before you commit

`audit_compose.py` scans every `docker-compose.yml` in this repo and flags
common issues — hardcoded secrets, missing resource limits, privileged
containers, port/name/volume conflicts between stacks, `.env` files at risk
of being committed, and more.

```bash
# Full audit
python3 audit_compose.py .

# Only the serious stuff
python3 audit_compose.py . --high-only

# Fail (exit 1) if anything HIGH severity is found — useful as a pre-commit check
python3 audit_compose.py . --fail-on-high

# List every host-side bind-mount path in use, to sanity-check .gitignore
python3 audit_compose.py . --list-volumes
```

Run it before every commit, or wire `--fail-on-high` into a pre-commit hook.

## Network

*(Optional: note here if services sit behind a reverse proxy / Cloudflare
Tunnel, which subnet/VLAN they're on, or how DNS is wired up, so future-you
remembers the topology.)*