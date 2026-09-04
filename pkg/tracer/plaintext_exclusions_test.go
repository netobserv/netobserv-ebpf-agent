package tracer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeExePath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "unchanged", in: "/usr/bin/app", want: "/usr/bin/app"},
		{name: "deleted suffix", in: "/usr/bin/app (deleted)", want: "/usr/bin/app"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeExePath(tt.in); got != tt.want {
				t.Fatalf("normalizeExePath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestReadProcComm(t *testing.T) {
	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc")
	pidDir := filepath.Join(proc, "1234")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("myapp\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	orig := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = orig })

	if got := readProcComm("1234"); got != "myapp" {
		t.Fatalf("readProcComm = %q, want myapp", got)
	}
	if got := readProcComm("missing"); got != "" {
		t.Fatalf("readProcComm(missing) = %q, want empty", got)
	}
}

func TestResolveProcExeFallback(t *testing.T) {
	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc")
	pidDir := filepath.Join(proc, "42")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("worker\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	orig := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = orig })

	exePath := filepath.Join(pidDir, "exe")
	resolved, comm := resolveProcExe("42", exePath)
	if comm != "worker" {
		t.Fatalf("comm = %q, want worker", comm)
	}
	if resolved != exePath {
		t.Fatalf("resolved = %q, want %q when symlink eval fails", resolved, exePath)
	}
}
