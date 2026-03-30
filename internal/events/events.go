// Package events defines the core event types for Sentinel security monitoring.
package events

import "time"

// Event is the base event type with shared fields.
type Event struct {
	Timestamp float64 `json:"timestamp"`
	Type      string  `json:"type"`
}

// NewEvent creates a base event with the current timestamp.
func NewEvent(eventType string) Event {
	return Event{
		Timestamp: float64(time.Now().UnixNano()) / 1e9,
		Type:      eventType,
	}
}

// ProcessEvent represents a process lifecycle event.
type ProcessEvent struct {
	Event
	Action   string   `json:"action"`
	PID      int      `json:"pid"`
	PPID     int      `json:"ppid"`
	UID      int      `json:"uid"`
	Comm     string   `json:"comm"`
	Filename string   `json:"filename"`
	Argv     []string `json:"argv"`
	ExitCode *int     `json:"exit_code"`
}

// NewProcessEvent creates a ProcessEvent with defaults.
func NewProcessEvent() *ProcessEvent {
	return &ProcessEvent{
		Event: NewEvent("process"),
		Argv:  []string{},
	}
}

// SyscallEvent represents a system call event.
type SyscallEvent struct {
	Event
	PID         int    `json:"pid"`
	Comm        string `json:"comm"`
	SyscallNr   int    `json:"syscall_nr"`
	SyscallName string `json:"syscall_name"`
	Args        []int  `json:"args"`
}

// NewSyscallEvent creates a SyscallEvent with defaults.
func NewSyscallEvent() *SyscallEvent {
	return &SyscallEvent{
		Event: NewEvent("syscall"),
		Args:  []int{},
	}
}

// FileEvent represents a filesystem event.
type FileEvent struct {
	Event
	Path      string `json:"path"`
	Operation string `json:"operation"`
	PID       *int   `json:"pid"`
	UID       *int   `json:"uid"`
}

// NewFileEvent creates a FileEvent with defaults.
func NewFileEvent() *FileEvent {
	return &FileEvent{
		Event: NewEvent("file"),
	}
}

// NetworkEvent represents a network connection event.
type NetworkEvent struct {
	Event
	PID      int    `json:"pid"`
	Comm     string `json:"comm"`
	SAddr    string `json:"saddr"`
	DAddr    string `json:"daddr"`
	SPort    int    `json:"sport"`
	DPort    int    `json:"dport"`
	Protocol string `json:"protocol"`
}

// NewNetworkEvent creates a NetworkEvent with defaults.
func NewNetworkEvent() *NetworkEvent {
	return &NetworkEvent{
		Event:    NewEvent("network"),
		Protocol: "tcp",
	}
}

// EventInterface allows probes to return any event type.
type EventInterface interface {
	GetTimestamp() float64
	GetType() string
}

// GetTimestamp returns the event timestamp.
func (e Event) GetTimestamp() float64 { return e.Timestamp }

// GetType returns the event type.
func (e Event) GetType() string { return e.Type }

// ToMap converts a ProcessEvent to a generic map for analysis.
func (e *ProcessEvent) ToMap() map[string]interface{} {
	m := map[string]interface{}{
		"timestamp":  e.Timestamp,
		"type":       e.Type,
		"event_type": e.Type,
		"action":     e.Action,
		"pid":        e.PID,
		"ppid":       e.PPID,
		"uid":        e.UID,
		"comm":       e.Comm,
		"filename":   e.Filename,
		"argv":       e.Argv,
	}
	if e.ExitCode != nil {
		m["exit_code"] = *e.ExitCode
	}
	return m
}

// ToMap converts a SyscallEvent to a generic map.
func (e *SyscallEvent) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"timestamp":    e.Timestamp,
		"type":         e.Type,
		"event_type":   e.Type,
		"pid":          e.PID,
		"comm":         e.Comm,
		"syscall_nr":   e.SyscallNr,
		"syscall_name": e.SyscallName,
		"args":         e.Args,
	}
}

// ToMap converts a FileEvent to a generic map.
func (e *FileEvent) ToMap() map[string]interface{} {
	m := map[string]interface{}{
		"timestamp":  e.Timestamp,
		"type":       e.Type,
		"event_type": e.Type,
		"path":       e.Path,
		"operation":  e.Operation,
	}
	if e.PID != nil {
		m["pid"] = *e.PID
	}
	if e.UID != nil {
		m["uid"] = *e.UID
	}
	return m
}

// ToMap converts a NetworkEvent to a generic map.
func (e *NetworkEvent) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"timestamp":  e.Timestamp,
		"type":       e.Type,
		"event_type": e.Type,
		"pid":        e.PID,
		"comm":       e.Comm,
		"saddr":      e.SAddr,
		"daddr":      e.DAddr,
		"sport":      e.SPort,
		"dport":      e.DPort,
		"protocol":   e.Protocol,
	}
}
