package tracer

import (
	"net"
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
)

func TestPickConnectionPrefersNetNSInterfaceIP(t *testing.T) {
	podIP := net.ParseIP("10.244.2.7")
	otherIP := net.ParseIP("10.244.1.2")
	conns := []procTCPConn{
		{
			localIP: otherIP, localPort: 8443,
			remoteIP: net.ParseIP("10.244.1.1"), remotePort: 36812,
			state: procTCPStateEstablished,
		},
		{
			localIP: podIP, localPort: 8443,
			remoteIP: net.ParseIP("10.244.2.1"), remotePort: 40494,
			state: procTCPStateEstablished,
		},
	}
	ports := map[uint16]struct{}{8443: {}}
	scoreOther := scoreConnection(&conns[0], model.PlaintextDirectionWrite, ports, nil, nil, []net.IP{podIP})
	scorePod := scoreConnection(&conns[1], model.PlaintextDirectionWrite, ports, nil, nil, []net.IP{podIP})
	if scorePod <= scoreOther {
		t.Fatalf("expected pod netns IP to score higher: pod=%d other=%d", scorePod, scoreOther)
	}

	s := NewPlaintextScope(nil, "", false, 0, 0)
	s.pidNetIPs[12345] = []net.IP{podIP}
	best := s.pickConnection(conns, model.PlaintextDirectionWrite, 12345)
	if best == nil || !best.localIP.Equal(podIP) {
		t.Fatalf("expected pod-local connection, got %#v", best)
	}
}

func TestPlaintextScopeSkipsEnrichWhenKernelTuplePresent(t *testing.T) {
	s := NewPlaintextScope(nil, "", false, 0, 0)
	rec := &model.PlaintextRecord{
		SrcAddr:   "10.244.2.7",
		DstAddr:   "10.244.2.1",
		SrcPort:   8443,
		DstPort:   40494,
		Protocol:  "TCP",
		Direction: model.PlaintextDirectionWrite,
	}
	s.enrichFiveTuple(rec, 12345)
	if rec.SrcAddr != "10.244.2.7" || rec.DstPort != 40494 {
		t.Fatalf("kernel tuple should be preserved, got %#v", rec)
	}
}
