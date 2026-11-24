package test

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// SkipUnlessWildcardListenerAccepts skips the current test or benchmark when
// a wildcard TCP listener — the kind of listener that the gRPC collectors
// started in the tests serve on (net.Listen("tcp", ":port")) — does not
// accept loopback connections from the given host (e.g. "127.0.0.1" or
// "::1").
//
// Go only binds wildcard listeners as dual-stack sockets ([::], serving both
// address families) when its one-shot IPv4-mapped-IPv6 capability probe
// succeeds. On single-stack hosts — or in restricted environments where that
// probe is denied, e.g. sandboxes that forbid binding IPv4-mapped IPv6
// addresses — the wildcard listener silently serves a single family, and any
// test dialing the other one would fail with connection-refused errors or
// long timeouts unrelated to the code under test.
func SkipUnlessWildcardListenerAccepts(tb testing.TB, host string) {
	skipUnlessListenerAccepts(tb, ":0", host)
}

// SkipUnlessLoopbackListenerAccepts skips the current test or benchmark when
// the given loopback host (e.g. "127.0.0.1" or "::1") cannot serve TCP
// connections, i.e. when neither listening on nor dialing that host works.
//
// Unlike SkipUnlessWildcardListenerAccepts, this does not depend on the
// runtime providing dual-stack wildcard listeners, so tests collecting from
// an explicitly bound listener stay usable on single-stack hosts and in
// restricted environments, as long as the address family itself is
// available.
func SkipUnlessLoopbackListenerAccepts(tb testing.TB, host string) {
	skipUnlessListenerAccepts(tb, net.JoinHostPort(host, "0"), host)
}

func skipUnlessListenerAccepts(tb testing.TB, listenAddr, host string) {
	tb.Helper()
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		tb.Skipf("cannot listen on TCP address %q: %v", listenAddr, err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), time.Second)
	if err != nil {
		tb.Skipf("TCP listener on %q does not accept %s connections "+
			"(single-stack or otherwise restricted network environment): %v", listenAddr, host, err)
	}
	_ = conn.Close()
}

func FreeTCPPortOn(host string) (int, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}
