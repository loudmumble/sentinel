package probes

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/loudmumble/sentinel/internal/config"
	"github.com/loudmumble/sentinel/internal/events"
)

// --- Process Probe Tests ---

func TestProcessProbeInitFallbackMode(t *testing.T) {
	p := NewProcessProbe(config.DefaultSentinelConfig())
	if p.Mode != "fallback" {
		t.Errorf("expected mode 'fallback', got %q", p.Mode)
	}
	if p.Running {
		t.Error("expected running=false initially")
	}
}

func TestProcessProbeScanProcReturnsPIDs(t *testing.T) {
	p := NewProcessProbe(config.DefaultSentinelConfig())
	pids := p.ScanProc()
	if len(pids) == 0 {
		t.Error("expected some PIDs from /proc")
	}
	myPID := os.Getpid()
	if _, ok := pids[myPID]; !ok {
		t.Errorf("expected current PID %d in scan results", myPID)
	}
}

func TestProcessProbeScanProcContainsCurrentProcess(t *testing.T) {
	p := NewProcessProbe(config.DefaultSentinelConfig())
	pids := p.ScanProc()
	myPID := os.Getpid()
	info, ok := pids[myPID]
	if !ok {
		t.Fatalf("current PID %d not found", myPID)
	}
	if _, ok := info["comm"]; !ok {
		t.Error("expected 'comm' in process info")
	}
	if _, ok := info["ppid"]; !ok {
		t.Error("expected 'ppid' in process info")
	}
	if _, ok := info["uid"]; !ok {
		t.Error("expected 'uid' in process info")
	}
}

func TestProcessProbeScanProcHasPID1(t *testing.T) {
	p := NewProcessProbe(config.DefaultSentinelConfig())
	pids := p.ScanProc()
	if _, ok := pids[1]; !ok {
		t.Error("expected PID 1 in scan results")
	}
}

func TestProcessProbeStartSetsRunning(t *testing.T) {
	p := NewProcessProbe(config.DefaultSentinelConfig())
	p.Start()
	if !p.Running {
		t.Error("expected running=true after Start()")
	}
	if len(p.KnownPIDs) == 0 {
		t.Error("expected known PIDs after Start()")
	}
	p.Stop()
}

func TestProcessProbeStopClearsRunning(t *testing.T) {
	p := NewProcessProbe(config.DefaultSentinelConfig())
	p.Start()
	p.Stop()
	if p.Running {
		t.Error("expected running=false after Stop()")
	}
}

func TestProcessProbePollReturnsList(t *testing.T) {
	p := NewProcessProbe(config.DefaultSentinelConfig())
	p.Start()
	evts := p.Poll()
	// Poll may return nil (no new events) — just verify no panic
	_ = evts
	p.Stop()
}

func TestProcessProbePollDetectsNoChange(t *testing.T) {
	p := NewProcessProbe(config.DefaultSentinelConfig())
	p.Start()
	p.Poll() // first poll establishes baseline
	evts := p.Poll()
	for _, e := range evts {
		pe, ok := e.(*events.ProcessEvent)
		if ok && pe.Action != "exec" && pe.Action != "exit" {
			t.Errorf("unexpected action %q", pe.Action)
		}
	}
	p.Stop()
}

func TestProcessProbePollFallbackReturnsEvents(t *testing.T) {
	p := NewProcessProbe(config.DefaultSentinelConfig())
	p.KnownPIDs = map[int]map[string]interface{}{} // empty known = all new
	evts := p.PollFallback()
	if len(evts) == 0 {
		t.Error("expected events from fallback poll with empty known PIDs")
	}
	for _, e := range evts {
		if e.Action != "exec" {
			t.Errorf("expected action 'exec', got %q", e.Action)
		}
		if e.PID <= 0 {
			t.Errorf("expected positive PID, got %d", e.PID)
		}
	}
}

func TestProcessProbeExitDetection(t *testing.T) {
	p := NewProcessProbe(config.DefaultSentinelConfig())
	p.KnownPIDs = map[int]map[string]interface{}{
		99999: {"comm": "fake_proc", "ppid": 1, "uid": 0, "cmdline": ""},
	}
	evts := p.PollFallback()
	var exitEvents []*events.ProcessEvent
	for _, e := range evts {
		if e.Action == "exit" && e.PID == 99999 {
			exitEvents = append(exitEvents, e)
		}
	}
	if len(exitEvents) != 1 {
		t.Fatalf("expected 1 exit event for PID 99999, got %d", len(exitEvents))
	}
	if exitEvents[0].Comm != "fake_proc" {
		t.Errorf("expected comm 'fake_proc', got %q", exitEvents[0].Comm)
	}
}

// --- Syscall Probe Tests ---

func TestSyscallProbeInitFallback(t *testing.T) {
	s := NewSyscallProbe(config.DefaultSentinelConfig())
	if s.Mode != "fallback" {
		t.Errorf("expected mode 'fallback', got %q", s.Mode)
	}
}

func TestSyscallProbeStartStop(t *testing.T) {
	s := NewSyscallProbe(config.DefaultSentinelConfig())
	s.Start()
	if !s.Running {
		t.Error("expected running=true after Start()")
	}
	s.Stop()
	if s.Running {
		t.Error("expected running=false after Stop()")
	}
}

func TestSyscallProbePollReturnsList(t *testing.T) {
	s := NewSyscallProbe(config.DefaultSentinelConfig())
	s.Start()
	evts := s.Poll()
	// Poll may return nil (no active syscalls) — just verify no panic
	_ = evts
	s.Stop()
}

func TestSyscallProbeFallbackReadsProc(t *testing.T) {
	s := NewSyscallProbe(config.DefaultSentinelConfig())
	evts := s.PollFallback()
	// May be empty if /proc/[pid]/syscall is not readable
	for _, e := range evts {
		if e.PID <= 0 {
			t.Errorf("expected positive PID, got %d", e.PID)
		}
	}
}

func TestSyscallEventHasNr(t *testing.T) {
	s := NewSyscallProbe(config.DefaultSentinelConfig())
	evts := s.PollFallback()
	if len(evts) > 0 {
		// Just verify it's an int (which it always is)
		_ = evts[0].SyscallNr
	}
}

// --- File Probe Tests ---

func TestFileProbeInit(t *testing.T) {
	f := NewFileProbe(config.DefaultSentinelConfig())
	if f.Running {
		t.Error("expected running=false initially")
	}
}

func TestFileProbeInotifyConstants(t *testing.T) {
	if InModify != 0x00000002 {
		t.Errorf("IN_MODIFY = %#x, want 0x00000002", InModify)
	}
	if InCreate != 0x00000100 {
		t.Errorf("IN_CREATE = %#x, want 0x00000100", InCreate)
	}
	if InDelete != 0x00000200 {
		t.Errorf("IN_DELETE = %#x, want 0x00000200", InDelete)
	}
	if InMovedFrom != 0x00000040 {
		t.Errorf("IN_MOVED_FROM = %#x, want 0x00000040", InMovedFrom)
	}
	if InMovedTo != 0x00000080 {
		t.Errorf("IN_MOVED_TO = %#x, want 0x00000080", InMovedTo)
	}
}

func TestFileProbeStartCreatesFd(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultSentinelConfig()
	cfg.WatchPaths = []string{dir}
	f := NewFileProbe(cfg)
	f.Start()
	defer f.Stop()
	if !f.HasFd {
		t.Error("expected HasFd=true after Start()")
	}
	if f.Fd < 0 {
		t.Error("expected non-negative fd")
	}
	if !f.Running {
		t.Error("expected running=true")
	}
	if len(f.WdMap) != 1 {
		t.Errorf("expected 1 watch, got %d", len(f.WdMap))
	}
}

func TestFileProbeStopCleansUp(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultSentinelConfig()
	cfg.WatchPaths = []string{dir}
	f := NewFileProbe(cfg)
	f.Start()
	f.Stop()
	if f.Running {
		t.Error("expected running=false after Stop()")
	}
	if f.HasFd {
		t.Error("expected HasFd=false after Stop()")
	}
}

func TestFileProbeEmptyPollWithoutStart(t *testing.T) {
	f := NewFileProbe(config.DefaultSentinelConfig())
	evts := f.Poll()
	if len(evts) != 0 {
		t.Errorf("expected empty events, got %d", len(evts))
	}
}

func TestFileProbeDetectsCreate(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultSentinelConfig()
	cfg.WatchPaths = []string{dir}
	f := NewFileProbe(cfg)
	f.Start()
	defer f.Stop()

	testFile := filepath.Join(dir, "test_create.txt")
	os.WriteFile(testFile, []byte("hello"), 0644)
	time.Sleep(100 * time.Millisecond)

	evts := f.Poll()
	if len(evts) == 0 {
		t.Error("expected events after file creation")
		return
	}
	var ops []string
	for _, e := range evts {
		if fe, ok := e.(*events.FileEvent); ok {
			ops = append(ops, fe.Operation)
		}
	}
	hasCreateOrModify := false
	for _, op := range ops {
		if op == "create" || op == "modify" {
			hasCreateOrModify = true
			break
		}
	}
	if !hasCreateOrModify {
		t.Errorf("expected 'create' or 'modify' in ops, got %v", ops)
	}
}

func TestFileProbeDetectsDelete(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "to_delete.txt")
	os.WriteFile(testFile, []byte("bye"), 0644)

	cfg := config.DefaultSentinelConfig()
	cfg.WatchPaths = []string{dir}
	f := NewFileProbe(cfg)
	f.Start()
	defer f.Stop()

	// Drain any pending events from creation
	f.Poll()
	os.Remove(testFile)
	time.Sleep(100 * time.Millisecond)

	evts := f.Poll()
	hasDelete := false
	for _, e := range evts {
		if fe, ok := e.(*events.FileEvent); ok && fe.Operation == "delete" {
			hasDelete = true
			break
		}
	}
	if !hasDelete {
		t.Error("expected 'delete' event")
	}
}

// --- Network Probe Tests ---

func TestNetworkProbeInitFallback(t *testing.T) {
	n := NewNetworkProbe(config.DefaultSentinelConfig())
	if n.Mode != "fallback" {
		t.Errorf("expected mode 'fallback', got %q", n.Mode)
	}
}

func TestNetworkProbeStartStop(t *testing.T) {
	n := NewNetworkProbe(config.DefaultSentinelConfig())
	n.Start()
	if !n.Running {
		t.Error("expected running=true after Start()")
	}
	n.Stop()
	if n.Running {
		t.Error("expected running=false after Stop()")
	}
}

func TestParseHexAddrLocalhost(t *testing.T) {
	ip, port := ParseHexAddr("0100007F:1F90")
	if ip != "127.0.0.1" {
		t.Errorf("expected IP '127.0.0.1', got %q", ip)
	}
	if port != 8080 {
		t.Errorf("expected port 8080, got %d", port)
	}
}

func TestParseHexAddrZero(t *testing.T) {
	ip, port := ParseHexAddr("00000000:0000")
	if ip != "0.0.0.0" {
		t.Errorf("expected IP '0.0.0.0', got %q", ip)
	}
	if port != 0 {
		t.Errorf("expected port 0, got %d", port)
	}
}

func TestParseHexAddrPort22(t *testing.T) {
	_, port := ParseHexAddr("00000000:0016")
	if port != 22 {
		t.Errorf("expected port 22, got %d", port)
	}
}

func TestNetworkProbeFallbackReturnsList(t *testing.T) {
	n := NewNetworkProbe(config.DefaultSentinelConfig())
	evts := n.PollFallback()
	// Can be empty on systems with no ESTABLISHED connections
	_ = evts
}

func TestNetworkProbeReturnsNetworkEvents(t *testing.T) {
	n := NewNetworkProbe(config.DefaultSentinelConfig())
	evts := n.PollFallback()
	for _, e := range evts {
		if e.Protocol != "tcp" {
			t.Errorf("expected protocol 'tcp', got %q", e.Protocol)
		}
	}
}

func TestNetworkProbeKnownConnsTracking(t *testing.T) {
	n := NewNetworkProbe(config.DefaultSentinelConfig())
	first := n.PollFallback()
	second := n.PollFallback()
	if len(second) > len(first) {
		t.Error("second poll should have <= events than first (tracking known conns)")
	}
}
