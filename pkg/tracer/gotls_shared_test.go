package tracer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsGoExecutable(t *testing.T) {
	if !isGoExecutable(os.Args[0]) {
		t.Fatalf("expected test binary %q to be recognized as Go executable", os.Args[0])
	}
	if isGoExecutable(filepath.Join(t.TempDir(), "missing")) {
		t.Fatal("missing file must not be recognized as Go executable")
	}
}

func TestStatInode(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "bin")
	if err := os.WriteFile(file, []byte("go"), 0o755); err != nil {
		t.Fatal(err)
	}

	dev, ino, err := statInode(file)
	if err != nil {
		t.Fatalf("statInode: %v", err)
	}
	if dev == 0 || ino == 0 {
		t.Fatalf("expected non-zero dev/inode, got dev=%d ino=%d", dev, ino)
	}

	if _, _, err := statInode(filepath.Join(tmp, "missing")); err == nil {
		t.Fatal("expected error for missing file")
	}
}
