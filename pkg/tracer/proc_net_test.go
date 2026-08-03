package tracer

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestParseProcNetAddrIPv4(t *testing.T) {
	ip, port, err := parseProcNetAddr("0100007F:1F90", false)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "127.0.0.1" || port != 8080 {
		t.Fatalf("got %s:%d", ip, port)
	}
}

func TestParseProcNetAddrIPv4MappedIPv6(t *testing.T) {
	ip, port, err := parseProcNetAddr("0000000000000000FFFF00000202F40A:20FB", true)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.244.2.2" {
		t.Fatalf("got %s, want 10.244.2.2", ip)
	}
	if port != 8443 {
		t.Fatalf("got port %d, want 8443", port)
	}

	ip2, _, err := parseProcNetAddr("0000000000000000FFFF00005D00800A:20FB", true)
	if err != nil {
		t.Fatal(err)
	}
	if ip2.String() != "10.128.0.93" {
		t.Fatalf("got %s, want 10.128.0.93", ip2)
	}
}

func TestPidsWithIPv4MappedIPv6(t *testing.T) {
	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc")
	pidDir := filepath.Join(proc, "843", "net")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tcp6 := "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   1: 0000000000000000FFFF00000202F40A:20FB 0000000000000000FFFF00000502F40A:89D0 01 00000000:00000000 00:00000000 00000000     0        0 0 1 00000000\n"
	if err := os.WriteFile(filepath.Join(pidDir, "tcp6"), []byte(tcp6), 0o644); err != nil {
		t.Fatal(err)
	}

	orig := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = orig })

	pids := pidsWithIP(net.ParseIP("10.244.2.2"))
	if _, ok := pids[843]; !ok {
		t.Fatalf("expected pid 843 in %v", pids)
	}
}

func TestPidsWithIP(t *testing.T) {
	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc")
	pidDir := filepath.Join(proc, "4242", "net")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0B00007F:1F90 0100007F:0050 01 00000000:00000000 00:00000000 00000000  1000        0 123 1 00000000\n"
	if err := os.WriteFile(filepath.Join(pidDir, "tcp"), []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}

	orig := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = orig })

	pids := pidsWithIP(net.ParseIP("127.0.0.11"))
	if _, ok := pids[4242]; !ok {
		t.Fatalf("expected pid 4242 in %v", pids)
	}
}

func TestPlaintextScopePIDFilterAndDedup(t *testing.T) {
	scope := NewPlaintextScope(nil, "42", true, time.Second, 0)
	scope.allowedPIDs = map[int]struct{}{42: {}}
	scope.pidScopeActive = true

	rec := &model.PlaintextRecord{Pid: 42, Data: []byte("GET /"), Direction: model.PlaintextDirectionWrite}
	if !scope.Process(rec) {
		t.Fatal("expected allowed pid to pass")
	}
	if scope.Process(rec) {
		t.Fatal("expected duplicate to be dropped")
	}

	rec2 := &model.PlaintextRecord{Pid: 99, Data: []byte("GET /"), Direction: model.PlaintextDirectionWrite}
	if scope.Process(rec2) {
		t.Fatal("expected disallowed pid to be dropped")
	}
}

func TestPlaintextScopeMatchesProcessIDNotThreadID(t *testing.T) {
	scope := NewPlaintextScope(nil, "42", false, time.Second, 0)
	scope.allowedPIDs = map[int]struct{}{42: {}}
	scope.pidScopeActive = true

	// Go TLS hooks often fire on worker threads: TGID=42 in high bits, tid=99 in low bits.
	rec := &model.PlaintextRecord{Pid: 42, Tgid: 99, Data: []byte("gotls-test-pod"), Direction: model.PlaintextDirectionWrite}
	if !scope.Process(rec) {
		t.Fatal("expected process ID from high bits to match peer_ip PID scope")
	}
}

func TestPlaintextScopeKTLSBypassesPIDAllowlist(t *testing.T) {
	scope := NewPlaintextScope([]*FilterConfig{{
		PeerIP: "10.129.0.37",
		Port:   intstr.FromInt32(8443),
	}}, "", false, time.Second, 0)
	scope.pidScopeActive = true
	// Simulate peer_ip scope refresh with no hostPID: allowed set stays empty.
	scope.allowedPIDs = map[int]struct{}{}

	rec := &model.PlaintextRecord{
		Pid:       12345,
		Data:      []byte("ktls-test-pod path=/"),
		Direction: model.PlaintextDirectionWrite,
		TLSSource: model.TLSSourceKTLS,
	}
	if !scope.Process(rec) {
		t.Fatal("expected kTLS plaintext to pass without PID allowlist when peer_ip is set")
	}
}

func TestPlaintextScopeKTLSAllowsZeroPID(t *testing.T) {
	scope := NewPlaintextScope([]*FilterConfig{{
		PeerIP: "10.244.0.5",
		Port:   intstr.FromInt32(8443),
	}}, "", false, time.Second, 0)
	scope.pidScopeActive = true
	scope.allowedPIDs = map[int]struct{}{}

	rec := &model.PlaintextRecord{
		Pid:       0,
		Data:      []byte("ktls-test-pod path=/"),
		Direction: model.PlaintextDirectionWrite,
		TLSSource: model.TLSSourceKTLS,
	}
	if !scope.Process(rec) {
		t.Fatal("expected kTLS plaintext with pid 0 to pass when peer_ip is scoped")
	}
	if rec.SrcAddr != "10.244.0.5" || rec.SrcPort != 8443 {
		t.Fatalf("expected partial 5-tuple from peer_ip scope, got %s:%d -> %s:%d", rec.SrcAddr, rec.SrcPort, rec.DstAddr, rec.DstPort)
	}
}

func TestPlaintextScopeAllowsPlaintextWithoutTupleWhenPortFiltered(t *testing.T) {
	scope := NewPlaintextScope([]*FilterConfig{{
		Port: intstr.FromInt32(8443),
	}}, "", false, time.Second, 0)

	rec := &model.PlaintextRecord{
		Pid:       12345,
		Data:      []byte("openssl-test-pod path=/"),
		Direction: model.PlaintextDirectionWrite,
		TLSSource: model.TLSSourceOpenSSL,
	}
	if !scope.Process(rec) {
		t.Fatal("expected OpenSSL plaintext without 5-tuple to pass when only --port is scoped")
	}
}

func TestPlaintextScopePeerIPOnlyPartialTuple(t *testing.T) {
	scope := NewPlaintextScope([]*FilterConfig{{
		PeerIP: "10.244.2.2",
	}}, "", false, time.Second, 0)

	rec := &model.PlaintextRecord{
		Pid:       0,
		Data:      []byte("GET / HTTP/1.1"),
		Direction: model.PlaintextDirectionWrite,
		TLSSource: model.TLSSourceKTLS,
	}
	if !scope.Process(rec) {
		t.Fatal("expected kTLS plaintext with peer_ip only")
	}
	if rec.SrcAddr != "10.244.2.2" {
		t.Fatalf("expected partial SrcAddr from peer_ip, got %q", rec.SrcAddr)
	}
}

func TestPlaintextScopePortOnlyPartialTuple(t *testing.T) {
	scope := NewPlaintextScope([]*FilterConfig{{
		Port: intstr.FromInt32(8443),
	}}, "", false, time.Second, 0)

	rec := &model.PlaintextRecord{
		Pid:       0,
		Data:      []byte("GET / HTTP/1.1"),
		Direction: model.PlaintextDirectionWrite,
		TLSSource: model.TLSSourceKTLS,
	}
	if !scope.Process(rec) {
		t.Fatal("expected kTLS plaintext with port only")
	}
	if rec.SrcPort != 8443 {
		t.Fatalf("expected partial SrcPort from port filter, got %d", rec.SrcPort)
	}
}

func TestPidsWithFilterPorts(t *testing.T) {
	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc")
	pidDir := filepath.Join(proc, "843", "net")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tcp6 := "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   1: 0000000000000000FFFF00000202F40A:20FB 0000000000000000FFFF00000502F40A:89D0 01 00000000:00000000 00:00000000 00000000     0        0 0 1 00000000\n"
	if err := os.WriteFile(filepath.Join(pidDir, "tcp6"), []byte(tcp6), 0o644); err != nil {
		t.Fatal(err)
	}

	orig := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = orig })

	pids := pidsWithFilterPorts(map[uint16]struct{}{8443: {}})
	if _, ok := pids[843]; !ok {
		t.Fatalf("expected pid 843 in %v", pids)
	}
}

func TestPlaintextScopePortOnlyEnrichesFromProc(t *testing.T) {
	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc")
	pidDir := filepath.Join(proc, "843", "net")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tcp6 := "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   1: 0000000000000000FFFF00000202F40A:20FB 0000000000000000FFFF00000502F40A:89D0 01 00000000:00000000 00:00000000 00000000     0        0 0 1 00000000\n"
	if err := os.WriteFile(filepath.Join(pidDir, "tcp6"), []byte(tcp6), 0o644); err != nil {
		t.Fatal(err)
	}

	orig := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = orig })

	scope := NewPlaintextScope([]*FilterConfig{{
		Port: intstr.FromInt32(8443),
	}}, "", false, time.Second, 0)

	rec := &model.PlaintextRecord{
		Pid:       0,
		Data:      []byte("GET / HTTP/1.1"),
		Direction: model.PlaintextDirectionWrite,
		TLSSource: model.TLSSourceKTLS,
	}
	if !scope.Process(rec) {
		t.Fatal("expected port-only enrichment from /proc")
	}
	if rec.SrcAddr != "10.244.2.2" || rec.DstAddr != "10.244.2.5" || rec.SrcPort != 8443 {
		t.Fatalf("unexpected tuple: %s:%d -> %s:%d", rec.SrcAddr, rec.SrcPort, rec.DstAddr, rec.DstPort)
	}
}

func TestPlaintextScopeMinBytes(t *testing.T) {
	scope := NewPlaintextScope(nil, "", false, time.Second, 4)

	short := &model.PlaintextRecord{Pid: 1, Data: []byte{0x89, 0x00}, Direction: model.PlaintextDirectionRead}
	if scope.Process(short) {
		t.Fatal("expected payload below min bytes to be dropped")
	}

	ok := &model.PlaintextRecord{Pid: 1, Data: []byte("GET /"), Direction: model.PlaintextDirectionWrite}
	if !scope.Process(ok) {
		t.Fatal("expected payload at or above min bytes to pass")
	}

	disabled := NewPlaintextScope(nil, "", false, time.Second, 0)
	tiny := &model.PlaintextRecord{Pid: 1, Data: []byte{0x89}, Direction: model.PlaintextDirectionRead}
	if !disabled.Process(tiny) {
		t.Fatal("expected min bytes 0 to allow tiny payloads")
	}
}

func TestParseProcNetEstablishedFilter(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "tcp")
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 123 1 00000000\n" +
		"   1: 0F00810A:01BB 1C763EC2:B871 01 00000000:00000000 00:00000000 00000000  1000        0 124 1 00000000\n"
	if err := os.WriteFile(path, []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}
	conns, err := parseProcNetFile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	usable := filterUsableProcTCPConns(conns)
	if len(usable) != 1 {
		t.Fatalf("expected 1 established conn, got %d", len(usable))
	}
	if usable[0].localIP.String() != "10.129.0.15" || usable[0].remotePort != 47217 {
		t.Fatalf("unexpected tuple: %s:%d -> %s:%d", usable[0].localIP, usable[0].localPort, usable[0].remoteIP, usable[0].remotePort)
	}
}
