//go:build ebpf

package probes

import (
	"sync"
	"time"

	syscalldcore "github.com/loudmumble/syscalld/core"
	syscalldsensors "github.com/loudmumble/syscalld/sensors"

	"github.com/loudmumble/sentinel/internal/events"
)

// SyscalldAdapter integrates syscalld into Sentinel as a probe.
// It starts a full SensorManager with all 7 sensors and translates their
// events into Sentinel's EventInterface, buffering them for Poll().
//
// Usage:
//
//	adapter := probes.NewSyscalldAdapter(nil)
//	adapter.Start()
//	evts := adapter.Poll()   // call periodically
//	adapter.Stop()
type SyscalldAdapter struct {
	mgr    *syscalldcore.SensorManager
	buf    chan events.EventInterface
	mu     sync.Mutex
	stopCh chan struct{}
}

// NewSyscalldAdapter creates an adapter with all 7 sensors registered.
// Pass a *syscalldcore.SensorFilter to restrict monitoring scope, or nil for defaults.
func NewSyscalldAdapter(filters *syscalldcore.SensorFilter) *SyscalldAdapter {
	mgr := syscalldcore.NewSensorManager(filters)
	mgr.Add(syscalldsensors.NewSyscallSensor())
	mgr.Add(syscalldsensors.NewProcessSensor())
	mgr.Add(syscalldsensors.NewFilesystemSensor())
	mgr.Add(syscalldsensors.NewNetworkSensor())
	mgr.Add(syscalldsensors.NewMemorySensor())
	mgr.Add(syscalldsensors.NewModuleSensor())
	mgr.Add(syscalldsensors.NewDnsSensor())

	a := &SyscalldAdapter{
		mgr:    mgr,
		buf:    make(chan events.EventInterface, 512),
		stopCh: make(chan struct{}),
	}

	// Fan all sensor events into the buffer channel.
	mgr.OnAny(func(e syscalldcore.Event) {
		se := convertEvent(e)
		if se == nil {
			return
		}
		select {
		case a.buf <- se:
		default:
			// Drop oldest to make room when buffer is full.
			select {
			case <-a.buf:
			default:
			}
			select {
			case a.buf <- se:
			default:
			}
		}
	})

	return a
}

// Start begins event collection.
func (a *SyscalldAdapter) Start() {
	a.mgr.Start()
}

// Stop halts event collection and cleans up sensors.
func (a *SyscalldAdapter) Stop() {
	a.mgr.Stop()
}

// Poll drains all buffered events accumulated since the last call.
func (a *SyscalldAdapter) Poll() []events.EventInterface {
	var out []events.EventInterface
	for {
		select {
		case e := <-a.buf:
			out = append(out, e)
		default:
			return out
		}
	}
}

// Healths returns runtime health snapshots for all underlying sensors.
func (a *SyscalldAdapter) Healths() []syscalldcore.SensorHealth {
	return a.mgr.Healths()
}

// ---------------------------------------------------------------------------
// Event conversion — syscalld core.Event → sentinel events.EventInterface
// ---------------------------------------------------------------------------

// convertEvent converts a syscalld event to a Sentinel EventInterface.
// Returns nil for unhandled or canary events (canary is infrastructure-only).
func convertEvent(e syscalldcore.Event) events.EventInterface {
	switch e.GetEventType() {
	case "syscall":
		return convertSyscall(e)
	case "process":
		return convertProcess(e)
	case "file":
		return convertFile(e)
	case "network":
		return convertNetwork(e)
	case "memory", "dns", "module":
		return &genericEventWrapper{raw: e.ToSentinelEvent()}
	case "canary":
		// Canary events are pipeline health signals, not security events.
		return nil
	default:
		return &genericEventWrapper{raw: e.ToSentinelEvent()}
	}
}

func convertSyscall(e syscalldcore.Event) events.EventInterface {
	m := e.ToSentinelEvent()
	se := events.NewSyscallEvent()
	se.Timestamp = asFloat64(m["timestamp"])
	se.PID = asInt(m["pid"])
	se.Comm = asString(m["comm"])
	se.SyscallNr = asInt(m["syscall_nr"])
	se.SyscallName = asString(m["syscall_name"])
	if args, ok := m["args"].([]int); ok {
		se.Args = args
	}
	return se
}

func convertProcess(e syscalldcore.Event) events.EventInterface {
	m := e.ToSentinelEvent()
	pe := events.NewProcessEvent()
	pe.Timestamp = asFloat64(m["timestamp"])
	pe.PID = asInt(m["pid"])
	pe.PPID = asInt(m["ppid"])
	pe.UID = asInt(m["uid"])
	pe.Comm = asString(m["comm"])
	pe.Action = asString(m["action"])
	pe.Filename = asString(m["filename"])
	if argv, ok := m["argv"].([]string); ok {
		pe.Argv = argv
	}
	return pe
}

func convertFile(e syscalldcore.Event) events.EventInterface {
	m := e.ToSentinelEvent()
	fe := events.NewFileEvent()
	fe.Timestamp = asFloat64(m["timestamp"])
	fe.Path = asString(m["path"])
	fe.Operation = asString(m["operation"])
	if pid := asInt(m["pid"]); pid != 0 {
		fe.PID = &pid
	}
	if uid := asInt(m["uid"]); uid != 0 {
		fe.UID = &uid
	}
	return fe
}

func convertNetwork(e syscalldcore.Event) events.EventInterface {
	m := e.ToSentinelEvent()
	ne := events.NewNetworkEvent()
	ne.Timestamp = asFloat64(m["timestamp"])
	ne.PID = asInt(m["pid"])
	ne.Comm = asString(m["comm"])
	ne.SAddr = asString(m["saddr"])
	ne.DAddr = asString(m["daddr"])
	ne.SPort = asInt(m["sport"])
	ne.DPort = asInt(m["dport"])
	ne.Protocol = asString(m["protocol"])
	return ne
}

// ---------------------------------------------------------------------------
// genericEventWrapper wraps arbitrary map data as EventInterface for event
// types that have no direct sentinel equivalent (memory, dns, module).
// ---------------------------------------------------------------------------

type genericEventWrapper struct {
	raw map[string]interface{}
}

func (w *genericEventWrapper) GetTimestamp() float64 {
	return asFloat64(w.raw["timestamp"])
}

func (w *genericEventWrapper) GetType() string {
	if t, ok := w.raw["type"].(string); ok {
		return t
	}
	return "unknown"
}

// ---------------------------------------------------------------------------
// Type coercion helpers
// ---------------------------------------------------------------------------

func asFloat64(v interface{}) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	case int64:
		return float64(t)
	}
	return float64(time.Now().UnixNano()) / 1e9
}

func asInt(v interface{}) int {
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	case int64:
		return int(t)
	}
	return 0
}

func asString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
