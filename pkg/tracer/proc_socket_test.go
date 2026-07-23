package tracer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSocketInodeFromFD(t *testing.T) {
	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc", "4242", "fd")
	if err := os.MkdirAll(proc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[12345]", filepath.Join(proc, "7")); err != nil {
		t.Fatal(err)
	}
	orig := procRootDir
	procRootDir = filepath.Join(tmp, "proc")
	t.Cleanup(func() { procRootDir = orig })

	inode, ok := socketInodeFromFD(4242, 7)
	if !ok || inode != 12345 {
		t.Fatalf("expected inode 12345, got %d ok=%v", inode, ok)
	}
}

func TestConnectionByInode(t *testing.T) {
	conns := []procTCPConn{
		{inode: 99},
		{inode: 12345},
	}
	c := connectionByInode(conns, 12345)
	if c == nil || c.inode != 12345 {
		t.Fatalf("unexpected match %#v", c)
	}
}

func TestParseProcNetInode(t *testing.T) {
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0B00007F:1F90 0100007F:0050 01 00000000:00000000 00:00000000 00000000  1000        0 123 1 00000000\n"
	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc", "1", "net")
	if err := os.MkdirAll(proc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "tcp"), []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := procRootDir
	procRootDir = filepath.Join(tmp, "proc")
	t.Cleanup(func() { procRootDir = orig })

	conns, err := readProcTCPConns(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 1 || conns[0].inode != 123 {
		t.Fatalf("unexpected conns %#v", conns)
	}
}
