// Package probes implements security monitoring probes.
package probes

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/loudmumble/sentinel/internal/config"
	"github.com/loudmumble/sentinel/internal/events"
)

// ProcessProbe monitors process creation and termination via /proc.
type ProcessProbe struct {
	Config    config.SentinelConfig
	Running   bool
	Mode      string
	KnownPIDs map[int]map[string]interface{}
}

// NewProcessProbe creates a ProcessProbe in fallback mode.
func NewProcessProbe(cfg config.SentinelConfig) *ProcessProbe {
	return &ProcessProbe{
		Config:    cfg,
		Mode:      "fallback",
		KnownPIDs: make(map[int]map[string]interface{}),
	}
}

// Start begins process monitoring.
func (p *ProcessProbe) Start() {
	p.Running = true
	p.KnownPIDs = p.ScanProc()
}

// Stop ends process monitoring.
func (p *ProcessProbe) Stop() {
	p.Running = false
}

// Poll returns new and exited process events since last poll.
func (p *ProcessProbe) Poll() []events.EventInterface {
	currentPIDs := p.ScanProc()
	var evts []events.EventInterface

	// Detect new processes
	for pid, info := range currentPIDs {
		if _, known := p.KnownPIDs[pid]; !known {
			e := events.NewProcessEvent()
			e.Action = "exec"
			e.PID = pid
			if ppid, ok := info["ppid"].(int); ok {
				e.PPID = ppid
			}
			if uid, ok := info["uid"].(int); ok {
				e.UID = uid
			}
			if comm, ok := info["comm"].(string); ok {
				e.Comm = comm
			}
			if cmdline, ok := info["cmdline"].(string); ok && cmdline != "" {
				parts := strings.SplitN(cmdline, " ", 2)
				e.Filename = parts[0]
				e.Argv = strings.Split(strings.Replace(cmdline, "\x00", " ", -1), " ")
			}
			evts = append(evts, e)
		}
	}

	// Detect exited processes
	for pid, info := range p.KnownPIDs {
		if _, exists := currentPIDs[pid]; !exists {
			e := events.NewProcessEvent()
			e.Action = "exit"
			e.PID = pid
			if comm, ok := info["comm"].(string); ok {
				e.Comm = comm
			}
			evts = append(evts, e)
		}
	}

	p.KnownPIDs = currentPIDs
	return evts
}

// ScanProc reads /proc to discover running processes.
func (p *ProcessProbe) ScanProc() map[int]map[string]interface{} {
	pids := make(map[int]map[string]interface{})
	entries, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return pids
	}
	for _, pidDir := range entries {
		base := filepath.Base(pidDir)
		pid, err := strconv.Atoi(base)
		if err != nil {
			continue
		}
		info := map[string]interface{}{"pid": pid}

		// Read /proc/[pid]/status
		statusData, err := os.ReadFile(filepath.Join(pidDir, "status"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(statusData), "\n") {
			if strings.HasPrefix(line, "Name:") {
				info["comm"] = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			} else if strings.HasPrefix(line, "PPid:") {
				if v, err := strconv.Atoi(strings.TrimSpace(strings.SplitN(line, ":", 2)[1])); err == nil {
					info["ppid"] = v
				}
			} else if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(strings.SplitN(line, ":", 2)[1])
				if len(fields) > 0 {
					if v, err := strconv.Atoi(fields[0]); err == nil {
						info["uid"] = v
					}
				}
			}
		}

		// Read /proc/[pid]/cmdline
		cmdlineData, err := os.ReadFile(filepath.Join(pidDir, "cmdline"))
		if err == nil {
			cmdline := strings.Replace(string(cmdlineData), "\x00", " ", -1)
			info["cmdline"] = strings.TrimSpace(cmdline)
		} else {
			info["cmdline"] = ""
		}

		pids[pid] = info
	}
	return pids
}

// PollFallback is an exported version of the fallback poll for testing.
func (p *ProcessProbe) PollFallback() []*events.ProcessEvent {
	currentPIDs := p.ScanProc()
	var evts []*events.ProcessEvent

	for pid, info := range currentPIDs {
		if _, known := p.KnownPIDs[pid]; !known {
			e := events.NewProcessEvent()
			e.Action = "exec"
			e.PID = pid
			if ppid, ok := info["ppid"].(int); ok {
				e.PPID = ppid
			}
			if uid, ok := info["uid"].(int); ok {
				e.UID = uid
			}
			if comm, ok := info["comm"].(string); ok {
				e.Comm = comm
			}
			if cmdline, ok := info["cmdline"].(string); ok && cmdline != "" {
				parts := strings.SplitN(cmdline, " ", 2)
				e.Filename = parts[0]
			}
			evts = append(evts, e)
		}
	}

	for pid, info := range p.KnownPIDs {
		if _, exists := currentPIDs[pid]; !exists {
			e := events.NewProcessEvent()
			e.Action = "exit"
			e.PID = pid
			if comm, ok := info["comm"].(string); ok {
				e.Comm = comm
			}
			evts = append(evts, e)
		}
	}

	p.KnownPIDs = currentPIDs
	return evts
}

// String returns probe info.
func (p *ProcessProbe) String() string {
	return fmt.Sprintf("ProcessProbe(mode=%s, running=%v)", p.Mode, p.Running)
}
