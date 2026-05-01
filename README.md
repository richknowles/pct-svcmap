<div align="center">
  <img src="assets/icon.svg" width="160" alt="pct-svcmap"/>

  # pct-svcmap

  **Proxmox VE Service Discovery & Metadata Engine**

  *Maps every listening service from LXC containers and QEMU VMs down to nested Docker containers — then auto-tags your guests and generates professional reports.*

  ![Go](https://img.shields.io/badge/Go-1.24-00ADD8?style=flat-square&logo=go&logoColor=white)
  ![Platform](https://img.shields.io/badge/Platform-Proxmox%20VE-E57000?style=flat-square)
  ![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
  ![Dependencies](https://img.shields.io/badge/Dependencies-zero-brightgreen?style=flat-square)
</div>

---

## Quick Reference

```
Usage of pct-svcmap:
  -dry-run
        Show tags that would be applied (requires --tag)
  -filter string
        Filter by guest name glob pattern (filepath.Match)
  -format string
        Output format for summary/security reports: md, json (default "md")
  -include-stopped
        Include stopped/paused guests
  -nmap string
        nmap cross-validation mode: quick, default, full
  -node string
        Proxmox node name (default: hostname)
  -output string
        Write report to file (default: stdout)
  -report string
        Report type: md, json, summary, security, security-full
  -tag
        Apply auto-generated tags to guests
  -tag-categories string
        Tag categories: type,ports,docker,security,network,all (default "all")
  -timeout int
        Per-exec timeout in seconds (default 5)
  -verbose
        Verbose logging to stderr
  -workers int
        Concurrent worker count (default 10)
```

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Usage Examples](#usage-examples)
- [Service Detection](#service-detection)
- [Auto-Tagging](#auto-tagging)
- [Reports](#reports)
- [Security Warnings](#security-warnings)
- [Project Structure](#project-structure)
- [License](#license)

---

## Overview

`pct-svcmap` is a single-binary CLI tool that runs on a Proxmox VE node and builds a complete picture of what network services are running across your infrastructure. It speaks directly to `pvesh`, `pct`, and `qm` — no agent installation, no remote API tokens, no configuration files required.

For each LXC container and QEMU VM it finds, `pct-svcmap`:

1. Fetches all network interfaces and IPs
2. Identifies every listening port, its process name, and PID
3. Detects nested Docker containers and correlates their published ports
4. Optionally writes semantic tags back to Proxmox guest config
5. Outputs a structured Markdown or JSON report

---

## Features

- **Concurrent scanning** — configurable goroutine worker pool scans all guests simultaneously
- **5-second exec timeouts** — unresponsive guests never block the pool
- **Three-level service detection** — `ss` → `lsof` → `/proc/net/tcp` fallback chain handles minimal containers without standard tooling
- **Docker-aware** — discovers running containers and maps their published ports to the host IP
- **QEMU Guest Agent check** — verifies agent availability before attempting VM exec, skips gracefully if absent
- **Auto-tagging** — derives 20+ semantic tags from discovered services and writes them to Proxmox guest config
- **Strictly additive merges** — never overwrites or removes existing user-defined tags
- **Dry-run mode** — preview exactly which tags would be added before committing
- **Markdown reports** — executive summary, security warnings table, per-guest service breakdown
- **JSON export** — full structured dump for diffing, dashboards, or piping to `jq`
- **Guest name filtering** — `filepath.Match` glob patterns to target specific guests
- **Zero external dependencies** — pure Go stdlib, single static binary

---

## Architecture

```
cmd/pct-svcmap/
└── main.go              CLI flags, wiring, summary table output

proxmox/
├── types.go             JSON-to-struct mappings for all Proxmox API responses
├── client.go            RunCommand — single exec chokepoint with context timeout
└── node.go              NodeClient: pvesh / pct / qm wrappers

scanner/
├── types.go             GuestScanResult, Service, DockerContainer, ScanConfig
├── pool.go              ScanAll → buffered channel worker pool → scanGuest
├── services.go          ss → lsof → /proc/net/tcp fallback chain + risky flagging
└── docker.go            Docker discovery, pipe-delimited port parsing

tagger/
├── generate.go          Tag derivation rules (ports, docker, flags)
└── merge.go             Strictly-additive union, dry-run, pvesh write

reporter/
├── markdown.go          Full MD report with summary, warnings, per-guest sections
└── json.go              JSONReport schema with nested structs
```

### Data Flow

```
NodeClient.ListLXC / ListQEMU
         │
         ▼
  filter (status + glob)
         │
         ▼
  Worker Pool  ─────────────────────────────────────────────────────┐
  [goroutine 1]  [goroutine 2]  ...  [goroutine N]                  │
       │                                                             │
       ▼                                                             │
  GetLXCIPs / CheckQEMUAgent + GetQEMUIPs                           │
       │                                                             │
       ▼                                                             │
  DetectServices  ──► ss -Htupln                                    │
                  ──► lsof -i -nP -sTCP:LISTEN  (fallback)         │
                  ──► /proc/net/tcp parse        (fallback)         │
                  ──► flagRiskyServices                              │
       │                                                             │
       ▼                                                             │
  DetectDocker  ──► docker ps --format "{{.ID}}|..."               │
                                                                     │
       └─────────────────── GuestScanResult ──────────────────────┘
                                    │
                                    ▼
                         tagger.ApplyTags  (if --tag)
                         ParseTagString → unionTags → SetGuestTags
                                    │
                                    ▼
                    reporter.RenderMarkdown / RenderJSON
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Proxmox VE 7+ | Must run directly on a PVE node (or via SSH to one) |
| Go 1.24+ | Only needed to build from source |
| `pvesh` | Bundled with Proxmox VE |
| `pct` / `qm` | Bundled with Proxmox VE |
| QEMU Guest Agent | Required for VM network/service scanning (optional; VMs without it are skipped gracefully) |

> `pct-svcmap` executes commands directly inside guests via `pct exec` and `qm guest exec`. It does not require network access to the guests themselves.

---

## Installation

### Build from source

```bash
git clone https://github.com/richknowles/pct-svcmap.git
cd pct-svcmap
go build -o /usr/local/bin/pct-svcmap ./cmd/pct-svcmap/
```

### Verify

```bash
pct-svcmap --help
```

---

## Quick Start

```bash
# 1. Basic scan — prints a summary table of all running guests
pct-svcmap

# 2. Full Markdown report
pct-svcmap --report md

# 3. JSON report, piped to jq
pct-svcmap --report json | jq '.summary'

# 4. Preview tags without writing anything
pct-svcmap --tag --dry-run --verbose

# 5. Scan, tag, and save a report in one command
pct-svcmap --tag --report md --output /root/svcmap.md
```

---

## CLI Reference

| Flag | Type | Default | Description |
|---|---|---|---|
| `--node` | string | system hostname | Proxmox node name to query |
| `--workers` | int | `10` | Number of concurrent goroutines in the worker pool |
| `--timeout` | int | `5` | Per-exec timeout in seconds (applied to every individual `pct`/`qm`/`pvesh` call) |
| `--report` | string | _(none)_ | Report type: `md`, `json`, `summary`, `security`, `security-full`. Omit for compact table |
| `--format` | string | `md` | Output format for `summary`/`security`/`security-full` reports: `md` or `json` |
| `--output` | string | stdout | Write report to this file path instead of stdout |
| `--tag` | bool | `false` | Apply auto-generated tags to guest configs in Proxmox |
| `--dry-run` | bool | `false` | Log tag diffs without writing (requires `--tag`) |
| `--tag-categories` | string | `all` | Comma-separated tag categories to generate: `type`, `ports`, `docker`, `security`, `network`, `all` |
| `--nmap` | string | _(off)_ | Cross-validate with nmap from Proxmox host: `quick` (top-100), `default` (top-1000), `full` (all ports) |
| `--filter` | string | _(all)_ | `filepath.Match` glob to restrict scanning by guest name, e.g. `web-*` |
| `--include-stopped` | bool | `false` | Include stopped and paused guests in results (they appear as `skipped`) |
| `--verbose` | bool | `false` | Write debug logging to stderr |

> All output (report, summary table) goes to **stdout**. All logging goes to **stderr**. This means `pct-svcmap --report json | jq .` works cleanly.

---

## Usage Examples

### Scan a specific node

```bash
pct-svcmap --node pve1
```

### Scan with more workers for large clusters

```bash
pct-svcmap --node pve1 --workers 25
```

### Increase timeout for slow guests

```bash
pct-svcmap --timeout 15
```

### Filter to a subset of guests

```bash
# Only guests whose names start with "prod-"
pct-svcmap --filter "prod-*"

# Only a specific guest
pct-svcmap --filter "web-proxy"
```

### Apply tags — dry run first, then commit

```bash
# See what would change
pct-svcmap --tag --dry-run --verbose 2>&1 | grep dry-run

# Apply for real
pct-svcmap --tag
```

### Save a Markdown report

```bash
pct-svcmap --report md --output /root/reports/$(date +%F)-svcmap.md
```

### Export JSON and query with jq

```bash
# All guests running Docker
pct-svcmap --report json | jq '.guests[] | select(.docker_available)'

# All risky services
pct-svcmap --report json | jq '.guests[].services[] | select(.is_risky)'

# Summary only
pct-svcmap --report json | jq '.summary'
```

### Scan stopped guests too

```bash
pct-svcmap --include-stopped --report md
```

---

## Service Detection

For each running guest, `pct-svcmap` tries three methods in order, using the first that succeeds:

### 1. `ss -Htupln` (preferred)

Executed inside the guest via `pct exec` or `qm guest exec`. Provides:
- Protocol (tcp/udp)
- Bind address and port
- Process name and PID from the `users:` field

### 2. `lsof -i -nP -sTCP:LISTEN` (fallback)

Used when `ss` is absent (some minimal Alpine or BusyBox containers). Provides the same data minus UDP services.

### 3. `/proc/net/tcp` + `/proc/net/tcp6` (last resort)

Direct kernel file parsing. Available on virtually any Linux guest, even without `iproute2` or `lsof`. Hex-decodes little-endian addresses, reads only rows in state `0A` (LISTEN). Does not provide process names.

> **Timeout handling:** each exec call has its own `context.WithTimeout`. If a call times out, the fallback chain stops immediately — it does not attempt further methods — and the guest is marked `failed`. Other workers in the pool are unaffected.

The method used is recorded per-guest in both the Markdown and JSON reports (`detection_method` field).

---

## Auto-Tagging

When `--tag` is passed, `pct-svcmap` generates semantic tags from each scan result and merges them into the existing Proxmox guest tag string using `pvesh set .../config --tags`.

### Port-based tags

| Port(s) | Tag |
|---|---|
| 21 | `ftp` |
| 22 | `ssh` |
| 23 | `telnet` |
| 25 | `smtp` |
| 53 | `dns` |
| 80 | `http` |
| 389 | `ldap` |
| 443 | `https` |
| 636 | `ldaps` |
| 3000 | `grafana` |
| 3306 | `mysql` |
| 5000 | `registry` |
| 5432 | `postgres` |
| 5601 | `kibana` |
| 6379 | `redis` |
| 6443 | `k8s-api` |
| 8080 | `http-alt` |
| 8443 | `https-alt` |
| 9090 | `prometheus` |
| 9200 / 9300 | `elasticsearch` |
| 27017 | `mongodb` |

### Condition-based tags

| Condition | Tag |
|---|---|
| Guest is an LXC container | `lxc` |
| Guest is a QEMU VM | `vm` |
| Docker daemon detected | `docker` |
| Any world-accessible risky service found | `risky` |
| Guest has more than one IP | `multi-ip` |
| QEMU VM with no responding guest agent | `no-agent` |
| Docker image name (e.g. `nginx:latest`) | `nginx` |

### Merge safety

Tag merges are **strictly additive**. The algorithm:

1. Read existing tag string from Proxmox (`pvesh get .../config`)
2. Parse, splitting on both `;` and `,` (handles Proxmox version differences)
3. Compute the set union with generated tags
4. Write back only if the union differs from the original
5. Output is always semicolon-delimited (`pvesh` format)

Existing user-defined tags are **never removed or overwritten**.

### Dry-run mode

```bash
pct-svcmap --tag --dry-run --verbose
```

Logs a line for each guest that would change:

```
[dry-run] web-proxy (100): would add tags: docker, http, https, lxc, nginx
[dry-run] db-server (101): would add tags: mysql, risky, vm
```

No `pvesh set` calls are made.

---

## Reports

### Markdown report (`--report md`)

```markdown
# Proxmox Service Map — pve1 — 2026-04-21 14:30:00

## Summary

| Metric         | Value |
|----------------|-------|
| Node           | pve1  |
| Guests scanned | 12    |
| LXC containers | 9     |
| QEMU VMs       | 3     |
| Total services | 47    |
| Docker hosts   | 4     |
| Risky services | 2     |
| Scan errors    | 0     |
| Scan duration  | 3.2s  |

## Security Warnings

| Guest      | VMID | Port | Protocol | Bind    | Risk                                  |
|------------|------|------|----------|---------|---------------------------------------|
| db-server  | 101  | 3306 | tcp      | 0.0.0.0 | MySQL — unencrypted, world-accessible |
| old-ftp    | 115  | 21   | tcp      | 0.0.0.0 | FTP — plaintext credentials           |

## Guests

### web-proxy (100) [lxc] — running

**IPs:** 192.168.1.100
**Detection:** ss
**Tags (existing):** web
**Tags (generated):** docker, http, https, lxc, nginx

#### Services

| Port | Proto | Bind    | Process            | Risk |
|------|-------|---------|-------------------|------|
| 22   | tcp   | 0.0.0.0 | sshd (pid 1234)   |      |
| 80   | tcp   | 0.0.0.0 | nginx (pid 5678)  |      |
| 443  | tcp   | 0.0.0.0 | nginx (pid 5678)  |      |

#### Docker Containers

| Container  | Image        | Published Ports                              |
|------------|--------------|----------------------------------------------|
| nginx-svc  | nginx:latest | 0.0.0.0:80→80/tcp, 0.0.0.0:443→443/tcp      |
| whoami     | traefik/whoami:latest | 0.0.0.0:8080→80/tcp               |
```

### JSON report (`--report json`)

```json
{
  "generated_at": "2026-04-21T14:30:00Z",
  "node": "pve1",
  "scan_duration": "3.2s",
  "summary": {
    "total_guests": 12,
    "lxc_count": 9,
    "qemu_count": 3,
    "total_services": 47,
    "docker_hosts": 4,
    "risky_services": 2,
    "scan_errors": 0
  },
  "guests": [
    {
      "vmid": 100,
      "name": "web-proxy",
      "type": "lxc",
      "status": "running",
      "ips": ["192.168.1.100"],
      "services": [
        {
          "port": 80,
          "protocol": "tcp",
          "bind_addr": "0.0.0.0",
          "process_name": "nginx",
          "pid": 5678,
          "is_risky": false
        }
      ],
      "docker_available": true,
      "docker_containers": [
        {
          "id": "abc123def456",
          "name": "nginx-svc",
          "image": "nginx:latest",
          "ports": [
            {
              "host_ip": "0.0.0.0",
              "host_port": 80,
              "container_port": 80,
              "protocol": "tcp"
            }
          ]
        }
      ],
      "detection_method": "ss",
      "existing_tags": ["web"],
      "generated_tags": ["docker", "http", "https", "lxc", "nginx"],
      "merged_tags": ["docker", "http", "https", "lxc", "nginx", "web"],
      "tags_applied": true
    }
  ]
}
```

---

## Security Warnings

The following services trigger a `risky` tag and a **Security Warnings** section in the Markdown report when they are bound to `0.0.0.0` or `::` (world-accessible). Services bound only to `127.x.x.x` are not flagged.

| Port | Service | Risk |
|---|---|---|
| 21 | FTP | Plaintext credentials transmitted over the network |
| 23 | Telnet | Fully unencrypted protocol, trivially sniffable |
| 3306 | MySQL / MariaDB | Unencrypted traffic; default installs often have weak auth |
| 5432 | PostgreSQL | Unencrypted traffic when TLS not enforced |
| 6379 | Redis | Unauthenticated by default; trivial RCE if world-accessible |

---

## Project Structure

```
pct-svcmap/
├── assets/
│   └── icon.svg                  Project icon
├── cmd/
│   └── pct-svcmap/
│       └── main.go               CLI entry point, flag wiring, summary table
├── proxmox/
│   ├── client.go                 RunCommand with per-call context timeout
│   ├── node.go                   NodeClient — all pvesh/pct/qm wrappers
│   └── types.go                  JSON structs for Proxmox API responses
├── scanner/
│   ├── docker.go                 Docker discovery and port mapping
│   ├── pool.go                   ScanAll, goroutine worker pool, scanGuest
│   ├── services.go               ss/lsof/proc fallback chain, risky flagging
│   └── types.go                  GuestScanResult, Service, DockerContainer
├── tagger/
│   ├── generate.go               Tag derivation from scan results
│   └── merge.go                  Additive merge, dry-run, pvesh write
├── reporter/
│   ├── json.go                   JSON report schema and renderer
│   └── markdown.go               Markdown report renderer
├── go.mod                        Module: github.com/rightontron/pct-svcmap
├── .gitignore
└── LICENSE
```

---

## License

MIT © 2026 Rich Knowles
