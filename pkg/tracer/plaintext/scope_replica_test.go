package plaintext

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// writeFakePIDNetNS creates /proc/<pid>/exe (pointing at exeTarget) and /proc/<pid>/ns/net.
// When nsSource is non-empty the ns/net entry is hardlinked to it so both PIDs share a
// network namespace inode (same pod); otherwise a fresh file gives a distinct namespace.
func writeFakePIDNetNS(t *testing.T, proc string, pid int, exeTarget, nsSource string) string {
	t.Helper()
	pidDir := filepath.Join(proc, strconv.Itoa(pid))
	nsDir := filepath.Join(pidDir, "ns")
	if err := os.MkdirAll(nsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exeTarget, filepath.Join(pidDir, "exe")); err != nil {
		t.Fatal(err)
	}
	nsNet := filepath.Join(nsDir, "net")
	if nsSource != "" {
		if err := os.Link(nsSource, nsNet); err != nil {
			t.Fatal(err)
		}
	} else if err := os.WriteFile(nsNet, []byte("netns"), 0o644); err != nil {
		t.Fatal(err)
	}
	return nsNet
}

// TestScopeDoesNotAttributeSiblingReplica reproduces NETOBSERV-2858: two replicas of one
// deployment on a node share the libssl inode, so the uprobe fires for the unscoped
// replica too. Its plaintext must be dropped, not misattributed to the scoped pod.
func TestScopeDoesNotAttributeSiblingReplica(t *testing.T) {
	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc")
	if err := os.MkdirAll(proc, 0o755); err != nil {
		t.Fatal(err)
	}

	// Both replicas run the same binary (shared executable inode).
	exe := filepath.Join(tmp, "server")
	if err := os.WriteFile(exe, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}

	const podAPID = 1000                                // scoped pod
	const podBPID = 2000                                // sibling replica, not scoped
	nsA := writeFakePIDNetNS(t, proc, podAPID, exe, "") // netns A
	writeFakePIDNetNS(t, proc, podBPID, exe, "")        // netns B (distinct file -> distinct inode)
	// A worker thread in pod A shares pod A's netns (hardlinked ns/net inode).
	const podAWorkerPID = 1001
	writeFakePIDNetNS(t, proc, podAWorkerPID, exe, nsA)

	orig := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = orig })

	scope := NewScope(nil, "", "", false, 0, 0)
	scope.pidScopeActive = true
	scope.allowedPIDs = map[int]struct{}{podAPID: {}}

	// Sibling replica: its executable matches pod A but it lives in a different netns.
	if got := scope.allowedPIDSharingExecutable(podBPID); got != 0 {
		t.Fatalf("allowedPIDSharingExecutable(podB) = %d, want 0 (different netns)", got)
	}
	if pid, decided := scope.scopedTargetPIDForEventNetNS(podBPID); !decided || pid != 0 {
		t.Fatalf("scopedTargetPIDForEventNetNS(podB) = (%d, %v), want (0, true) drop", pid, decided)
	}

	// A worker thread of the scoped pod shares its netns and must still resolve to pod A.
	if got := scope.allowedPIDSharingExecutable(podAWorkerPID); got != podAPID {
		t.Fatalf("allowedPIDSharingExecutable(podAWorker) = %d, want %d", got, podAPID)
	}
	if pid, decided := scope.scopedTargetPIDForEventNetNS(podAWorkerPID); !decided || pid != podAPID {
		t.Fatalf("scopedTargetPIDForEventNetNS(podAWorker) = (%d, %v), want (%d, true)", pid, decided, podAPID)
	}
}

// TestScopedTargetFallbackWhenNetNSUnknown keeps best-effort attribution for single-pod
// captures where the scoped PID's namespace cannot be resolved (e.g. synthetic PIDs).
func TestScopedTargetFallbackWhenNetNSUnknown(t *testing.T) {
	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc")
	if err := os.MkdirAll(proc, 0o755); err != nil {
		t.Fatal(err)
	}
	// Event PID has a resolvable netns, but the scoped PID (999999) has none.
	const eventPID = 3000
	writeFakePIDNetNS(t, proc, eventPID, filepath.Join(tmp, "x"), "")

	orig := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = orig })

	scope := NewScope(nil, "", "", false, 0, 0)
	scope.pidScopeActive = true
	scope.allowedPIDs = map[int]struct{}{999999: {}}

	if _, decided := scope.scopedTargetPIDForEventNetNS(eventPID); decided {
		t.Fatal("expected no netns decision when scoped PID namespace is unknown")
	}
}
