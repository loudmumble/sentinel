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

// SyscallProbe monitors system calls via /proc/[pid]/syscall.
type SyscallProbe struct {
	Config  config.SentinelConfig
	Running bool
	Mode    string
}

// NewSyscallProbe creates a SyscallProbe in fallback mode.
func NewSyscallProbe(cfg config.SentinelConfig) *SyscallProbe {
	return &SyscallProbe{
		Config: cfg,
		Mode:   "fallback",
	}
}

// Start begins syscall monitoring.
func (s *SyscallProbe) Start() {
	s.Running = true
}

// Stop ends syscall monitoring.
func (s *SyscallProbe) Stop() {
	s.Running = false
}

// Poll returns syscall events from the first 50 PIDs.
func (s *SyscallProbe) Poll() []events.EventInterface {
	var evts []events.EventInterface
	for _, e := range s.PollFallback() {
		evts = append(evts, e)
	}
	return evts
}

// PollFallback reads /proc/[pid]/syscall for the first 50 PIDs.
func (s *SyscallProbe) PollFallback() []*events.SyscallEvent {
	var evts []*events.SyscallEvent
	entries, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return evts
	}
	limit := 50
	if len(entries) < limit {
		limit = len(entries)
	}
	for _, pidDir := range entries[:limit] {
		data, err := os.ReadFile(filepath.Join(pidDir, "syscall"))
		if err != nil {
			continue
		}
		content := strings.TrimSpace(string(data))
		parts := strings.Fields(content)
		if len(parts) < 1 {
			continue
		}
		nr, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(filepath.Base(pidDir))
		if err != nil {
			continue
		}

		e := events.NewSyscallEvent()
		e.PID = pid
		e.SyscallNr = nr

		// Parse hex args
		var args []int
		for _, arg := range parts[1:4] {
			if strings.HasPrefix(arg, "0x") {
				if v, err := strconv.ParseInt(arg[2:], 16, 64); err == nil {
					args = append(args, int(v))
				}
			}
		}
		e.Args = args
		evts = append(evts, e)
	}
	return evts
}

// String returns probe info.
func (s *SyscallProbe) String() string {
	return fmt.Sprintf("SyscallProbe(mode=%s, running=%v)", s.Mode, s.Running)
}
