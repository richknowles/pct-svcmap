# pct-svcmap — Claude Instructions

## Git Identity — MANDATORY
Before making ANY commit, run:
```bash
git config user.name "Rich Knowles"
git config user.email "rich@itwerks.net"
```
Every commit must show **Rich Knowles <rich@itwerks.net>**. No Co-Authored-By. No Claude attribution.

## What This Is
Proxmox LXC/VM/Docker service discovery with IP:PORT mapping.
Scans all running guests on a Proxmox node and maps every listening service.

Built in Go. Zero external dependencies.

## Stack
- Language: Go 1.24
- No external dependencies (stdlib only)
- Runs on the Proxmox host directly (needs `pct` in PATH)

## Architecture
```
cmd/pct-svcmap/main.go   CLI entrypoint — flags, orchestration, table output
scanner/                 Core discovery engine
  services.go            ss → lsof → /proc/net/tcp fallback chain
  docker.go              Docker container port discovery
  pool.go                Concurrent worker pool
  types.go               GuestScanResult, Service, ScanConfig types
proxmox/                 Proxmox host interaction
  client.go              pct/qm exec wrapper
  node.go                Guest listing via pvesh
  types.go               Guest, ExecConfig types
reporter/                Output formatters
  json.go                Structured JSON output
  markdown.go            GitHub-flavored markdown table
tagger/                  Proxmox tag management
  generate.go            Auto-tag rules from discovered services
  merge.go               Tag merging and application via pvesh
```

## Key Design Decisions
- Uses `pct exec {vmid} -- ss -Htupln` as primary detection method
- Falls back to `lsof`, then `/proc/net/tcp` parsing
- Docker: calls `docker ps --format json` inside containers that have Docker
- No Proxmox API auth — all operations use `pct`/`qm` CLI tools
- Concurrent workers (default 10) for speed across many guests

## Integration with oz-monitor
oz-monitor (LOO/oz-monitor) wraps pct-svcmap via subprocess:
- POST `/api/svcmap/scan` triggers a new scan
- GET `/api/svcmap` returns cached JSON result
- Frontend SERVICE MAP tab shows discovered IP:PORT mappings with SCAN button

## Build
```bash
go build -o pct-svcmap ./cmd/pct-svcmap/
```

## Usage
```bash
./pct-svcmap                          # summary table
./pct-svcmap --report json            # JSON output
./pct-svcmap --report json | jq .     # pretty JSON
./pct-svcmap --tag                    # apply auto-tags to guests
./pct-svcmap --filter "plexiq"        # scan specific guest
```
