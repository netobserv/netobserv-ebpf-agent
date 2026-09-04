package tracer

import "testing"

func TestPlaintextScopeActiveForDiscovery(t *testing.T) {
	if (&PlaintextScope{}).IsPIDScopeActive() {
		t.Fatal("empty scope must not be active")
	}
	scope := NewPlaintextScope([]*FilterConfig{{
		PeerIP: "10.244.0.5",
	}}, "", false, 0, 0)
	if !scope.IsPIDScopeActive() {
		t.Fatal("peer_ip scope must be active")
	}
}
