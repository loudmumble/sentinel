# Sentinel

**Security monitoring toolkit for Linux with optional LLM-powered analysis**

Sentinel is a low-overhead security observability agent designed for deep system visibility. It monitors processes, syscalls, files, and network connections using `/proc` and `inotify`, with optional eBPF sensor integration. Designed for resilience, Sentinel provides continuous monitoring across diverse Linux distributions without kernel-version dependencies.

## Key Features

- **Process Monitoring** — Tracks process execution and termination events via `/proc` scanning, capturing full command-line arguments, parent-child relationships, and UID metadata.
- **Syscall Auditing** — Monitors system calls in real-time via `/proc/[pid]/syscall`. Detects suspicious patterns including `memfd_create` (in-memory payload staging) and process name masquerading via `prctl`.
- **File Integrity Monitoring (FIM)** — Uses `inotify` via `golang.org/x/sys/unix` to monitor critical system paths for unauthorized modifications, creations, or deletions.
- **Network Observability** — Detects TCP connection establishment events by monitoring `/proc/net/tcp`, correlating network activity with specific processes.
- **Heuristic Analysis Engine** — Built-in detection for common attack vectors including root shell spawns, critical system file tampering, and connections to unusual privileged ports.
- **Behavioral Correlation** — Identifies complex event sequences via a sliding 5-second window, such as `exec_then_connect` (process spawn followed by immediate outbound connection) and `fork_then_memfd` (process spawn followed by in-memory file creation).
- **Multi-Output Pipeline** — Supports human-readable console output, structured JSON for SIEM ingestion, and Common Event Format (CEF) for legacy log managers.
- **LLM-Powered Analysis** — Optional [Ollama](https://ollama.com) integration for AI-driven event triage, process classification, and attack narrative generation.
- **MCP Server** — JSON-RPC server on stdio for agentic integration via the [Model Context Protocol](https://modelcontextprotocol.io).
- **Web Dashboard** — Built-in HTTP API and real-time dashboard with event visualization, probe control, and LLM analysis endpoints.

## Installation

### Pre-built Binaries

Download a binary from the [Releases](https://github.com/loudmumble/sentinel/releases) page. No runtime dependencies required.

```bash
chmod +x sentinel-linux-amd64
./sentinel-linux-amd64 status
```

### Build from Source

Requires Go 1.24+.

```bash
git clone https://github.com/loudmumble/sentinel.git
cd sentinel
make build    # produces build/sentinel
```

## Quick Start

Check probe availability:

```bash
sentinel status
```

Start process monitoring:

```bash
sentinel monitor --output human
```

Trace syscalls with anomaly detection:

```bash
sentinel trace --output json
```

Watch directories for file integrity changes:

```bash
sentinel watch --paths /etc,/var/www/html
```

Run ad-hoc event analysis:

```bash
sentinel analyze --type process --pid 1 --comm bash --uid 0
```

Start the MCP server for agentic integration:

```bash
sentinel serve
```

## Configuration

Sentinel uses environment variable overrides and CLI flags.

| Variable | Description | Default |
|----------|-------------|---------|
| `OLLAMA_URL` | Ollama API endpoint | `http://localhost:11434` |
| `SENTINEL_MODEL` | Default LLM model | `llama3.2` |
| `SENTINEL_TRIAGE_MODEL` | Fast triage model | Falls back to `SENTINEL_MODEL` |
| `SENTINEL_DEEP_MODEL` | Deep analysis model | Falls back to `SENTINEL_MODEL` |

See [`.env.example`](.env.example) for a full template.

Default monitoring parameters:

| Parameter | Default |
|-----------|---------|
| Probes | `process`, `syscall`, `file`, `network` |
| Watch paths | `/etc`, `/usr/bin` |
| Syscall filter | `execve`, `connect`, `open`, `unlink` |
| Alert threshold | `75` |
| Output format | `json` |

## Architecture

Sentinel operates as a producer-consumer pipeline:

1. **Probes** — `/proc` and `inotify`-based event producers with optional eBPF sensor integration via [syscalld](https://github.com/loudmumble/syscalld).
2. **Analysis Engine** — Enriches events with metadata and evaluates them against heuristic rules.
3. **Correlator** — Tracks events over a sliding 5-second window to identify multi-stage behaviors.
4. **Output Pipeline** — Formats and filters results based on severity and configuration.
5. **LLM Layer** — Optional Ollama-backed AI triage, classification, and narrative generation.

For a detailed breakdown, see [ARCHITECTURE.md](ARCHITECTURE.md).

## CLI Reference

| Command | Description |
|---------|-------------|
| `sentinel status` | Probe availability, LLM backend status, and configuration |
| `sentinel monitor` | Process monitoring via `/proc` polling |
| `sentinel trace` | Syscall tracing with anomaly detection |
| `sentinel watch` | File integrity monitoring via inotify |
| `sentinel analyze` | Ad-hoc anomaly detection on a described event |
| `sentinel serve` | MCP JSON-RPC server on stdio |
| `sentinel version` | Print version |

### Common Flags

- `--output [json|cef|human]` — Select output format (available on `monitor`, `trace`, `watch`)
- `--interval INT` — Poll interval in seconds (available on `monitor`, `trace`)
- `--paths PATH,...` — Comma-separated directories to monitor (`watch` only)

### Analyze Flags

| Flag | Description |
|------|-------------|
| `--type` | Event type: `process`, `file`, `network`, `syscall` |
| `--pid` | Process ID |
| `--comm` | Process command name |
| `--path` | File path (for file events) |
| `--operation` | File operation: `create`, `modify`, `delete` |
| `--uid` | User ID |
| `--dport` | Destination port (for network events) |

## Testing

169 Go tests covering all modules.

```bash
make test
```

## License

AGPL-3.0 — See [LICENSE](LICENSE) for details.

## Contributing

Issues and pull requests are welcome. Please open an issue first to discuss significant changes.
