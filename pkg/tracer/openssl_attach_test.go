package tracer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveOpenSSLLibPath(t *testing.T) {
	tmp := t.TempDir()
	lib := filepath.Join(tmp, "libssl.so.3")
	if err := os.WriteFile(lib, []byte{0}, 0o644); err != nil {
		t.Fatal(err)
	}

	if got := resolveOpenSSLLibPath(lib); got != lib {
		t.Fatalf("expected %q, got %q", lib, got)
	}

	missing := filepath.Join(tmp, "missing.so")
	if got := resolveOpenSSLLibPath(missing); got != missing {
		t.Fatalf("expected unchanged path %q, got %q", missing, got)
	}
}

func TestResolveOpenSSLLibPathPrefersHostMount(t *testing.T) {
	tmp := t.TempDir()
	hostRoot := filepath.Join(tmp, "host")
	hostLib := filepath.Join(hostRoot, "usr", "lib64", "libssl.so.3")
	containerLib := filepath.Join(tmp, "usr", "lib64", "libssl.so.3")
	if err := os.MkdirAll(filepath.Dir(hostLib), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(containerLib), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostLib, []byte{1}, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(containerLib, []byte{2}, 0o644); err != nil {
		t.Fatal(err)
	}

	orig := opensslHostRoot
	opensslHostRoot = hostRoot
	t.Cleanup(func() { opensslHostRoot = orig })

	defaultPath := filepath.Join(string(filepath.Separator), "usr", "lib64", "libssl.so.3")
	got := resolveOpenSSLLibPath(defaultPath)
	if got != hostLib {
		t.Fatalf("expected host mount %q, got %q", hostLib, got)
	}
}

func TestDiscoverLibSSLAttachPathsUsesProcRoot(t *testing.T) {
	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc")
	pid := "4242"
	containerLib := filepath.Join(proc, pid, "root", "usr", "lib64", "libssl.so.3")
	if err := os.MkdirAll(filepath.Dir(containerLib), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(containerLib, []byte{1}, 0o644); err != nil {
		t.Fatal(err)
	}
	maps := "7f0000000000-7f0000100000 r-xp 00000000 00:00 0 /usr/lib64/libssl.so.3\n"
	if err := os.WriteFile(filepath.Join(proc, pid, "maps"), []byte(maps), 0o644); err != nil {
		t.Fatal(err)
	}

	origProc := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = origProc })

	paths := discoverLibSSLAttachPaths(nil, nil)
	if len(paths) != 1 || paths[0] != containerLib {
		t.Fatalf("expected [%q], got %v", containerLib, paths)
	}
}

func TestDiscoverLibSSLAttachPathsSkipsExcludedPID(t *testing.T) {
	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc")

	writeProcEntry(t, proc, "1000", "kube-multus", filepath.Join(tmp, "multus"))
	containerLib := filepath.Join(proc, "2000", "root", "usr", "lib64", "libssl.so.3")
	if err := os.MkdirAll(filepath.Dir(containerLib), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(containerLib, []byte{1}, 0o644); err != nil {
		t.Fatal(err)
	}
	maps := "7f0000000000-7f0000100000 r-xp 00000000 00:00 0 /usr/lib64/libssl.so.3\n"
	if err := os.WriteFile(filepath.Join(proc, "2000", "maps"), []byte(maps), 0o644); err != nil {
		t.Fatal(err)
	}
	writeProcEntry(t, proc, "2000", "myapp", filepath.Join(tmp, "app"))

	origProc := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = origProc })

	paths := discoverLibSSLAttachPaths(nil, nil)
	if len(paths) != 1 || paths[0] != containerLib {
		t.Fatalf("expected [%q], got %v", containerLib, paths)
	}
}

func TestDiscoverLibSSLAttachPathsSkipsHostDefaultLib(t *testing.T) {
	tmp := t.TempDir()
	hostRoot := filepath.Join(tmp, "host")
	hostLib := filepath.Join(hostRoot, "usr", "lib64", "libssl.so.3")
	if err := os.MkdirAll(filepath.Dir(hostLib), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostLib, []byte{1}, 0o644); err != nil {
		t.Fatal(err)
	}

	origHost := opensslHostRoot
	origProc := procRootDir
	opensslHostRoot = hostRoot
	procRootDir = filepath.Join(tmp, "proc")
	t.Cleanup(func() {
		opensslHostRoot = origHost
		procRootDir = origProc
	})

	defaultPath := filepath.Join(string(filepath.Separator), "usr", "lib64", "libssl.so.3")
	_ = defaultPath
	paths := discoverLibSSLAttachPaths(nil, nil)
	if len(paths) != 0 {
		t.Fatalf("expected no host libssl attach paths, got %v", paths)
	}
}

func writeProcEntry(t *testing.T, proc, pid, comm, exeTarget string) {
	t.Helper()
	pidDir := filepath.Join(proc, pid)
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte(comm), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exeTarget, filepath.Join(pidDir, "exe")); err != nil {
		t.Fatal(err)
	}
}
