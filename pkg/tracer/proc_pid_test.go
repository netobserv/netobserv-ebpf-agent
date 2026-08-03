package tracer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestProcStatusTgid(t *testing.T) {
	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc")
	threadDir := filepath.Join(proc, "10726")
	if err := os.MkdirAll(threadDir, 0o755); err != nil {
		t.Fatal(err)
	}
	status := "Name:\tserver\nTgid:\t10651\nPid:\t10726\n"
	if err := os.WriteFile(filepath.Join(threadDir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}

	orig := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = orig })

	if got := procStatusTgid(10726); got != 10651 {
		t.Fatalf("procStatusTgid(10726) = %d, want 10651", got)
	}
}

func TestFindHostPIDsForInnerPID(t *testing.T) {
	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc")
	hostDir := filepath.Join(proc, "10651")
	if err := os.MkdirAll(hostDir, 0o755); err != nil {
		t.Fatal(err)
	}
	status := "Name:\tserver\nTgid:\t10651\nPid:\t10651\nNSpid:\t10651\t1\n"
	if err := os.WriteFile(filepath.Join(hostDir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}

	orig := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = orig })

	hosts := findHostPIDsForInnerPID(1)
	if len(hosts) != 1 || hosts[0] != 10651 {
		t.Fatalf("findHostPIDsForInnerPID(1) = %v, want [10651]", hosts)
	}
}

func TestResolvePlaintextHostPIDFromThread(t *testing.T) {
	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc")
	threadDir := filepath.Join(proc, "10726")
	if err := os.MkdirAll(threadDir, 0o755); err != nil {
		t.Fatal(err)
	}
	status := "Name:\tserver\nTgid:\t10651\nPid:\t10726\n"
	if err := os.WriteFile(filepath.Join(threadDir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}

	orig := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = orig })

	rec := &model.PlaintextRecord{Pid: 0, Tgid: 10726}
	if got := resolvePlaintextHostPID(rec); got != 10651 {
		t.Fatalf("resolvePlaintextHostPID = %d, want 10651", got)
	}
}

func TestPlaintextScopeProcessAdmitsScopedHostPID(t *testing.T) {
	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc")
	hostDir := filepath.Join(proc, "10651")
	pauseDir := filepath.Join(proc, "13574")
	threadDir := filepath.Join(proc, "10726")
	netDir := filepath.Join(hostDir, "net")
	pauseNetDir := filepath.Join(pauseDir, "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pauseNetDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(threadDir, 0o755); err != nil {
		t.Fatal(err)
	}
	hostStatus := "Name:\tserver\nTgid:\t10651\nPid:\t10651\nNSpid:\t10651\t1\n"
	if err := os.WriteFile(filepath.Join(hostDir, "status"), []byte(hostStatus), 0o644); err != nil {
		t.Fatal(err)
	}
	pauseStatus := "Name:\tpause\nTgid:\t13574\nPid:\t13574\nNSpid:\t13574\t1\n"
	if err := os.WriteFile(filepath.Join(pauseDir, "status"), []byte(pauseStatus), 0o644); err != nil {
		t.Fatal(err)
	}
	threadStatus := "Name:\tserver\nTgid:\t10651\nPid:\t10726\n"
	if err := os.WriteFile(filepath.Join(threadDir, "status"), []byte(threadStatus), 0o644); err != nil {
		t.Fatal(err)
	}
	tcp6 := "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   1: 0000000000000000FFFF00000901F80A:20FB 0000000000000000FFFF00000B01F80A:C350 01 00000000:00000000 00:00000000 00000000     0        0 0 1 00000000\n" +
		"   2: 00000000000000000000000000000000:20FB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0 1 00000000\n"
	if err := os.WriteFile(filepath.Join(netDir, "tcp6"), []byte(tcp6), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pauseNetDir, "tcp6"), []byte("  sl  local_address remote_address st\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	orig := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = orig })

	scope := NewPlaintextScope([]*FilterConfig{{
		PeerIP: "10.244.1.9",
		Port:   intstr.FromInt32(8443),
	}}, "", false, 0, 0)
	scope.admitPID(13574)
	scope.admitPID(10651)

	rec := &model.PlaintextRecord{
		Pid:  780232,
		Tgid: 0,
		Data: []byte("HTTP/1.1 200 OK\r\n\r\ngotls-test-pod"),
	}
	if !scope.Process(rec) {
		t.Fatal("expected plaintext record to pass with pause+server scoped PIDs")
	}
	if rec.SrcPort != 8443 && rec.DstPort != 8443 {
		t.Fatalf("expected enriched 5-tuple on port 8443, got src=%d dst=%d", rec.SrcPort, rec.DstPort)
	}
}
