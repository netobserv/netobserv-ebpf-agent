package tracer

import (
	"net"
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
)

func TestPickConnectionSkipsListenSocket(t *testing.T) {
	conns := []procTCPConn{
		{
			localIP: net.IPv4zero, localPort: 443,
			remoteIP: net.IPv4zero, remotePort: 0,
			state: 0x0A,
		},
		{
			localIP: net.ParseIP("10.129.0.15"), localPort: 443,
			remoteIP: net.ParseIP("194.62.118.28"), remotePort: 47217,
			state: procTCPStateEstablished,
		},
	}
	best := pickConnection(conns, model.PlaintextDirectionRead, map[uint16]struct{}{443: {}}, nil, nil)
	if best == nil || !best.remoteIP.Equal(net.ParseIP("194.62.118.28")) {
		t.Fatalf("expected established conn, got %#v", best)
	}
}

func TestFilterUsableProcTCPConns(t *testing.T) {
	conns := []procTCPConn{
		{localIP: net.IPv4zero, remoteIP: net.IPv4zero, localPort: 443, state: 0x0A},
		{
			localIP: net.ParseIP("10.129.0.15"), localPort: 443,
			remoteIP: net.ParseIP("82.67.17.14"), remotePort: 50230,
			state: procTCPStateEstablished,
		},
	}
	usable := filterUsableProcTCPConns(conns)
	if len(usable) != 1 || usable[0].remotePort != 50230 {
		t.Fatalf("unexpected usable conns: %#v", usable)
	}
}
