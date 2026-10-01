package plaintext

import (
	"net"
	"testing"
)

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
