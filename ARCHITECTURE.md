# Sentinel Architecture

## System Overview

Sentinel is designed as a modular observability pipeline that bridges the gap between kernel-level events and user-space security analysis. It prioritizes reliability by implementing a multi-mode sensing layer that adapts to the host environment's capabilities.

```text
┌─────────────────────────────────────────────────────┐
│                    SENTINEL CORE                    │
│                                                     │
│  ┌────────────┐      ┌──────────────┐      ┌─────┐  │
│  │   Probes   │      │   Analysis   │      │Corre│  │
│  │ (eBPF/Proc)├─────►│    Engine    ├─────►│lator│  │
│  └────────────┘      │ (Heuristics) │      └─┬───┘  │
│          ▲           └──────┬───────┘        │      │
│          │                  │                │      │
│  ┌───────┴────┐             │                ▼      │
│  │ Host Kernel│             │             ┌─────┐   │
│  └────────────┘             └────────────►│Alert│   │
│                                           │Pipe │   │
│                                           │line │   │
│                                           └─────┘   │
│                                              │      │
│  ┌────────────────────────────────────────┐  ▼      │
│  │               OUTPUT                   │┌─────┐  │
│  │      (Console, JSON, CEF)              │┤ SIEM│  │
│  └────────────────────────────────────────┘└─────┘  │
└─────────────────────────────────────────────────────┘
```

## Component Descriptions

### Probes (`internal/probes`)
The sensing layer consists of four specialized probes. Currently all operate in fallback mode; eBPF support is planned for Phase 2:
- **`ProcessProbe`**: Periodically scans `/proc` for new PIDs and compares state to detect process exec and exit events. Captures comm, cmdline, PPID, and UID.
- **`SyscallProbe`**: Reads `/proc/[pid]/syscall` for the first 50 PIDs to capture active syscall numbers and arguments.
- **`FileProbe`**: Implements file integrity monitoring using `inotify` via `golang.org/x/sys/unix` bindings. Monitors specific directories for create, modify, delete, and rename operations.
- **`NetworkProbe`**: Monitors `/proc/net/tcp` for new ESTABLISHED connections, parsing hex addresses and tracking known connections to detect new activity.

### Analysis Engine (`internal/analysis`)
The `AnalysisEngine` provides real-time enrichment and heuristic evaluation:
- **Enrichment**: Decorates raw probe events with human-readable timestamps and normalized event types.
- **Heuristics**: Applies predefined security rules (e.g., detecting `bash` spawns by root users or unauthorized modifications to `/etc/passwd`).
- **Scoring**: Assigns a numeric risk score (0-100) to each event based on rule severity.

### Correlator (`internal/analysis`)
The `Correlator` maintains a sliding 5-second window of events to detect cross-domain patterns.
- **`exec_then_connect`**: A critical signature where a process is executed and immediately initiates an outbound network connection, often indicative of reverse shells or automated exfiltration.

### Output (`internal/output`)
The output subsystem handles formatting and filtering:
- **`Formatters`**: Translates internal event maps into `JSON`, `CEF`, or `Human` (colorized markup) formats.
- **`OutputPipeline`**: Filters events based on a configurable `alert_threshold` and directs the final output to the system standard output for logging or SIEM collection.

## Data Flow

1. **Capture**: Probes extract events by polling `/proc` and reading `inotify` file descriptors.
2. **Enrichment**: Raw events are converted into a standardized map format with added context (timestamps, event types).
3. **Detection**: The `AnalysisEngine` scans the event for heuristic matches and calculates an initial score.
4. **Correlation**: Events are buffered in the `Correlator`. If a sequence of events matches a known pattern, a new `correlation` event is generated.
5. **Formatting**: The `OutputPipeline` selects the appropriate formatter based on configuration.
6. **Dispatch**: High-score alerts or all events (depending on configuration) are printed to the console.

## Performance Considerations

- **eBPF Efficiency** (planned): When eBPF mode is implemented, event filtering will happen in the kernel, significantly reducing the CPU overhead of monitoring high-frequency events like syscalls.
- **Fallback Impact**: In `fallback` mode, Sentinel uses optimized polling intervals and limited `/proc` scanning to maintain a low footprint while sacrificing some event resolution.
- **Stateless Analysis**: The engine is largely stateless, allowing it to process events with minimal memory overhead, while the correlator uses a strict time-bound sliding window.
