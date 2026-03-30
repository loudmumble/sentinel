package events

import (
	"testing"
)

func TestBaseEventDefaults(t *testing.T) {
	e := NewEvent("base")
	if e.Type != "base" {
		t.Errorf("expected type 'base', got %q", e.Type)
	}
	if e.Timestamp <= 0 {
		t.Error("expected positive timestamp")
	}
}

func TestBaseEventGetters(t *testing.T) {
	e := NewEvent("test")
	if e.GetType() != "test" {
		t.Errorf("GetType() = %q, want 'test'", e.GetType())
	}
	if e.GetTimestamp() <= 0 {
		t.Error("GetTimestamp() should be positive")
	}
}

func TestProcessEventDefaults(t *testing.T) {
	e := NewProcessEvent()
	if e.Type != "process" {
		t.Errorf("expected type 'process', got %q", e.Type)
	}
	if e.Action != "" {
		t.Errorf("expected empty action, got %q", e.Action)
	}
	if e.PID != 0 {
		t.Errorf("expected pid 0, got %d", e.PID)
	}
	if e.PPID != 0 {
		t.Errorf("expected ppid 0, got %d", e.PPID)
	}
	if e.UID != 0 {
		t.Errorf("expected uid 0, got %d", e.UID)
	}
	if e.Comm != "" {
		t.Errorf("expected empty comm, got %q", e.Comm)
	}
	if e.Filename != "" {
		t.Errorf("expected empty filename, got %q", e.Filename)
	}
	if len(e.Argv) != 0 {
		t.Errorf("expected empty argv, got %v", e.Argv)
	}
	if e.ExitCode != nil {
		t.Errorf("expected nil exit_code, got %v", e.ExitCode)
	}
}

func TestProcessEventWithValues(t *testing.T) {
	e := NewProcessEvent()
	e.Action = "exec"
	e.PID = 1234
	e.PPID = 1
	e.UID = 1000
	e.Comm = "bash"
	e.Filename = "/bin/bash"
	if e.Action != "exec" {
		t.Errorf("expected action 'exec', got %q", e.Action)
	}
	if e.PID != 1234 {
		t.Errorf("expected pid 1234, got %d", e.PID)
	}
	if e.Comm != "bash" {
		t.Errorf("expected comm 'bash', got %q", e.Comm)
	}
}

func TestSyscallEventDefaults(t *testing.T) {
	e := NewSyscallEvent()
	if e.Type != "syscall" {
		t.Errorf("expected type 'syscall', got %q", e.Type)
	}
	if e.PID != 0 {
		t.Errorf("expected pid 0, got %d", e.PID)
	}
	if e.SyscallNr != 0 {
		t.Errorf("expected syscall_nr 0, got %d", e.SyscallNr)
	}
	if e.SyscallName != "" {
		t.Errorf("expected empty syscall_name, got %q", e.SyscallName)
	}
	if len(e.Args) != 0 {
		t.Errorf("expected empty args, got %v", e.Args)
	}
}

func TestSyscallEventWithValues(t *testing.T) {
	e := NewSyscallEvent()
	e.PID = 42
	e.SyscallNr = 59
	e.SyscallName = "execve"
	e.Args = []int{1, 2, 3}
	if e.PID != 42 {
		t.Errorf("expected pid 42, got %d", e.PID)
	}
	if e.SyscallNr != 59 {
		t.Errorf("expected syscall_nr 59, got %d", e.SyscallNr)
	}
	if len(e.Args) != 3 || e.Args[0] != 1 || e.Args[1] != 2 || e.Args[2] != 3 {
		t.Errorf("expected args [1,2,3], got %v", e.Args)
	}
}

func TestFileEventDefaults(t *testing.T) {
	e := NewFileEvent()
	if e.Type != "file" {
		t.Errorf("expected type 'file', got %q", e.Type)
	}
	if e.Path != "" {
		t.Errorf("expected empty path, got %q", e.Path)
	}
	if e.Operation != "" {
		t.Errorf("expected empty operation, got %q", e.Operation)
	}
	if e.PID != nil {
		t.Errorf("expected nil pid, got %v", e.PID)
	}
	if e.UID != nil {
		t.Errorf("expected nil uid, got %v", e.UID)
	}
}

func TestFileEventWithValues(t *testing.T) {
	e := NewFileEvent()
	e.Path = "/etc/passwd"
	e.Operation = "modify"
	pid := 100
	uid := 0
	e.PID = &pid
	e.UID = &uid
	if e.Path != "/etc/passwd" {
		t.Errorf("expected path '/etc/passwd', got %q", e.Path)
	}
	if e.Operation != "modify" {
		t.Errorf("expected operation 'modify', got %q", e.Operation)
	}
}

func TestNetworkEventDefaults(t *testing.T) {
	e := NewNetworkEvent()
	if e.Type != "network" {
		t.Errorf("expected type 'network', got %q", e.Type)
	}
	if e.PID != 0 {
		t.Errorf("expected pid 0, got %d", e.PID)
	}
	if e.SAddr != "" {
		t.Errorf("expected empty saddr, got %q", e.SAddr)
	}
	if e.DAddr != "" {
		t.Errorf("expected empty daddr, got %q", e.DAddr)
	}
	if e.SPort != 0 {
		t.Errorf("expected sport 0, got %d", e.SPort)
	}
	if e.DPort != 0 {
		t.Errorf("expected dport 0, got %d", e.DPort)
	}
	if e.Protocol != "tcp" {
		t.Errorf("expected protocol 'tcp', got %q", e.Protocol)
	}
}

func TestNetworkEventWithValues(t *testing.T) {
	e := NewNetworkEvent()
	e.PID = 99
	e.SAddr = "10.0.0.1"
	e.DAddr = "8.8.8.8"
	e.SPort = 12345
	e.DPort = 443
	if e.DPort != 443 {
		t.Errorf("expected dport 443, got %d", e.DPort)
	}
	if e.SAddr != "10.0.0.1" {
		t.Errorf("expected saddr '10.0.0.1', got %q", e.SAddr)
	}
}

func TestProcessEventToMap(t *testing.T) {
	e := NewProcessEvent()
	e.Action = "exec"
	e.PID = 100
	e.Comm = "test"
	m := e.ToMap()
	if m["event_type"] != "process" {
		t.Errorf("expected event_type 'process', got %v", m["event_type"])
	}
	if m["action"] != "exec" {
		t.Errorf("expected action 'exec', got %v", m["action"])
	}
	if m["pid"] != 100 {
		t.Errorf("expected pid 100, got %v", m["pid"])
	}
}

func TestSyscallEventToMap(t *testing.T) {
	e := NewSyscallEvent()
	e.PID = 42
	e.SyscallNr = 319
	m := e.ToMap()
	if m["syscall_nr"] != 319 {
		t.Errorf("expected syscall_nr 319, got %v", m["syscall_nr"])
	}
}

func TestFileEventToMap(t *testing.T) {
	e := NewFileEvent()
	e.Path = "/etc/shadow"
	e.Operation = "modify"
	m := e.ToMap()
	if m["path"] != "/etc/shadow" {
		t.Errorf("expected path '/etc/shadow', got %v", m["path"])
	}
}

func TestNetworkEventToMap(t *testing.T) {
	e := NewNetworkEvent()
	e.DPort = 443
	e.DAddr = "8.8.8.8"
	m := e.ToMap()
	if m["dport"] != 443 {
		t.Errorf("expected dport 443, got %v", m["dport"])
	}
	if m["protocol"] != "tcp" {
		t.Errorf("expected protocol 'tcp', got %v", m["protocol"])
	}
}
