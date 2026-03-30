# Sentinel

**Security monitoring toolkit for Linux with /proc fallback and optional LLM-powered analysis**

Sentinel is a low-overhead security observability agent designed for deep system visibility. It monitors processes, syscalls, files, and network connections using `/proc` and `inotify`, with eBPF integration planned for a future release. Designed for resilience, Sentinel provides continuous monitoring across diverse Linux distributions without kernel-version dependencies.

## Key Features

- **Process Monitoring**: Tracks process execution (`exec`) and termination (`exit`) events via `/proc` scanning, capturing full command-line arguments, parent-child relationships, and UID metadata.
- **Syscall Auditing**: Monitors system calls in real-time via `/proc/[pid]/syscall`. Detects suspicious patterns including `memfd_create` (in-memory payload staging) and process name masquerading via `prctl`.
- **File Integrity Monitoring (FIM)**: Uses `inotify` via `golang.org/x/sys/unix` to monitor critical system paths (e.g., `/etc`, `/usr/bin`) for unauthorized modifications, creations, or deletions.
- **Network Observability**: Detects TCP connection establishment events by monitoring `/proc/net/tcp`, correlating network activity with specific processes.
- **Heuristic Analysis Engine**: Built-in detection for common attack vectors, including root shell spawns, critical system file tampering, and connections to unusual privileged ports.
- **Behavioral Correlation**: Identifies complex event sequences via a sliding 5-second window, such as `exec_then_connect` (process spawn followed by immediate outbound connection) and `fork_then_memfd` (process spawn followed by in-memory file creation).
- **Multi-Output Pipeline**: Supports human-readable console output, structured JSON for SIEM ingestion, and Common Event Format (CEF) for legacy log managers.
- **LLM-Powered Analysis**: Optional Ollama integration for AI-driven event triage, process classification, and attack narrative generation.
- **MCP Server**: JSON-RPC server on stdio for agentic integration via the Model Context Protocol.
- **Web Dashboard**: Built-in HTTP API and real-time dashboard with event visualization, probe control, and LLM analysis endpoints.

## Installation

A pre-built `linux/amd64` binary is in `build/`. No runtime dependencies required.

```bash
# Use pre-built binary (no dependencies needed)
./build/sentinel status

# Or build from source (requires Go 1.24+)
make build          # produces build/sentinel
```

## Quick Start

Check the status and availability of monitoring probes on your system:

```bash
sentinel status
```

Start the monitoring engine with process polling:

```bash
sentinel monitor --output human
```

Trace syscalls across processes:

```bash
sentinel trace --output json
```

Watch specific directories for file integrity changes:

```bash
sentinel watch --paths /etc,/var/www/html
```

Run an ad-hoc analysis on a security event:

```bash
sentinel analyze --type process --pid 1 --comm bash --uid 0
```

Start the MCP server for agentic integration:

```bash
sentinel serve
```

## Configuration

Sentinel uses Go-based configuration with environment variable overrides and CLI flags.

```bash
# Environment variables
OLLAMA_URL=http://localhost:11434    # Ollama API endpoint
SENTINEL_MODEL=hog-security-v2      # Default LLM model
SENTINEL_TRIAGE_MODEL=...           # Model for fast triage (falls back to SENTINEL_MODEL)
SENTINEL_DEEP_MODEL=...             # Model for deep analysis (falls back to SENTINEL_MODEL)
```

Default configuration parameters:

```
Probes:          process, syscall, file, network
Watch paths:     /etc, /usr/bin
Syscall filter:  execve, connect, open, unlink
Alert threshold: 75
Output format:   json
```

## Architecture Overview

Sentinel operates as a classic producer-consumer pipeline:

1. **Probes**: `/proc` and `inotify`-based event producers (eBPF planned for Phase 2).
2. **Analysis Engine**: Enriches events with metadata and evaluates them against heuristic rules.
3. **Correlator**: Tracks events over a sliding 5-second window to identify multi-stage behaviors.
4. **Output Pipeline**: Formats and filters results based on severity and configuration.
5. **LLM Layer**: Optional Ollama-backed AI triage, classification, and narrative generation.

For a detailed breakdown, see [ARCHITECTURE.md](ARCHITECTURE.md).

## CLI Reference

### `sentinel status`
Displays the current availability and operating mode of each probe, LLM backend status, and configuration.

### `sentinel monitor`
Starts process monitoring via `/proc` polling and streams events to the configured output.
- `--output [json|cef|human]`: Select output formatting.
- `--interval INT`: Poll interval in seconds (default: 1).

### `sentinel trace`
Syscall tracing via `/proc/[pid]/syscall` with anomaly detection.
- `--output [json|cef|human]`: Select output formatting.
- `--interval INT`: Poll interval in seconds (default: 1).

### `sentinel watch`
File integrity monitoring via inotify.
- `--paths PATH,...`: Comma-separated list of directories to monitor.
- `--output [json|cef|human]`: Select output formatting.

### `sentinel analyze`
Run anomaly detection on a described event.
- `--type [process|file|network|syscall]`: Event type.
- `--pid INT`: Process ID.
- `--comm STRING`: Process command name.
- `--path STRING`: File path (for file events).
- `--operation STRING`: File operation (create, modify, delete).
- `--uid INT`: User ID.
- `--dport INT`: Destination port (for network events).

### `sentinel serve`
Start the MCP (Model Context Protocol) JSON-RPC server on stdio for agentic integration. Exposes tools: `monitor`, `trace`, `watch`, `analyze`.

### `sentinel version`
Print the sentinel version.

## Cube Root Defense Suite

Sentinel is a core component of the **Cube Root Defense Suite**, providing the host-level observability layer that feeds into our higher-level analysis tools:

- **Phantom**: Offensive security orchestration and automated red-teaming.
- **Malscope**: AI-powered malware analysis sandbox.
- **Aegis**: Agentic intrusion detection and network cadence analysis.
- **Agora**: Centralized security intelligence and orchestration hub.

## Testing

159 Go tests covering all modules (probes, analysis engine, correlator, formatters, CLI, LLM integration, MCP server, web dashboard).

```bash
make test
# or
go test ./cmd/... ./internal/... -count=1 -v
```

## License

AGPL-3.0 — See [LICENSE](LICENSE) for details.

## Credits

Built by [LoudMumble](https://github.com/loudmumble).
