package probes

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/loudmumble/sentinel/internal/config"
	"github.com/loudmumble/sentinel/internal/events"
)

// NetworkProbe monitors network connections via /proc/net/tcp.
type NetworkProbe struct {
	Config     config.SentinelConfig
	Running    bool
	Mode       string
	KnownConns map[string]bool
}

// NewNetworkProbe creates a NetworkProbe in fallback mode.
func NewNetworkProbe(cfg config.SentinelConfig) *NetworkProbe {
	return &NetworkProbe{
		Config:     cfg,
		Mode:       "fallback",
		KnownConns: make(map[string]bool),
	}
}

// Start begins network monitoring.
func (n *NetworkProbe) Start() {
	n.Running = true
}

// Stop ends network monitoring.
func (n *NetworkProbe) Stop() {
	n.Running = false
}

// Poll returns new network connection events.
func (n *NetworkProbe) Poll() []events.EventInterface {
	var evts []events.EventInterface
	for _, e := range n.PollFallback() {
		evts = append(evts, e)
	}
	return evts
}

// PollFallback reads /proc/net/tcp for ESTABLISHED connections.
func (n *NetworkProbe) PollFallback() []*events.NetworkEvent {
	var evts []*events.NetworkEvent
	data, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return evts
	}

	lines := strings.Split(string(data), "\n")
	currentConns := make(map[string]bool)

	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		localAddr := fields[1]
		remAddr := fields[2]
		state := fields[3]

		// 01 = ESTABLISHED
		if state != "01" {
			continue
		}

		connID := fmt.Sprintf("%s-%s", localAddr, remAddr)
		currentConns[connID] = true

		if !n.KnownConns[connID] {
			lIP, lPort := ParseHexAddr(localAddr)
			rIP, rPort := ParseHexAddr(remAddr)
			e := events.NewNetworkEvent()
			e.SAddr = lIP
			e.DAddr = rIP
			e.SPort = lPort
			e.DPort = rPort
			e.Protocol = "tcp"
			evts = append(evts, e)
		}
	}

	n.KnownConns = currentConns
	return evts
}

// ParseHexAddr parses a hex IP:port pair from /proc/net/tcp.
func ParseHexAddr(hexAddr string) (string, int) {
	parts := strings.SplitN(hexAddr, ":", 2)
	if len(parts) != 2 {
		return "0.0.0.0", 0
	}

	portVal, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		portVal = 0
	}

	ipHex := parts[0]
	ipBytes, err := hex.DecodeString(ipHex)
	if err != nil || len(ipBytes) != 4 {
		return "0.0.0.0", int(portVal)
	}

	// Little-endian to IP
	ipInt := binary.LittleEndian.Uint32(ipBytes)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipInt)

	return ip.String(), int(portVal)
}

// String returns probe info.
func (n *NetworkProbe) String() string {
	return fmt.Sprintf("NetworkProbe(mode=%s, running=%v)", n.Mode, n.Running)
}
