package plaintext

import "testing"

func TestScopeActiveForDiscovery(t *testing.T) {
	if (&Scope{}).IsPIDScopeActive() {
		t.Fatal("empty scope must not be active")
	}
	scope := NewScope([]*FilterConfig{{
		PeerIP: "10.244.0.5",
	}}, "", false, 0, 0)
	if !scope.IsPIDScopeActive() {
		t.Fatal("peer_ip scope must be active")
	}
}
