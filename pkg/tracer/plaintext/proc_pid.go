package plaintext

import (
	"debug/buildinfo"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
)

// resolvePlaintextHostPID maps bpf pid_tgid fields to the host TGID used for /proc lookups.
// bpf_get_current_pid_tgid stores TGID in the upper 32 bits and thread ID in the lower 32 bits.
// Uprobe events can arrive with only the thread ID populated or with a container-local TGID.
func resolvePlaintextHostPID(rec *model.PlaintextRecord) int {
	if rec == nil {
		return 0
	}
	candidates := []int{int(rec.Pid), int(rec.Tgid)}
	seen := map[int]struct{}{}
	for _, candidate := range candidates {
		if candidate <= 0 {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		if tgid := procStatusTgid(candidate); tgid > 0 {
			return tgid
		}
	}
	for _, candidate := range candidates {
		if candidate <= 0 {
			continue
		}
		for _, hostPID := range findHostPIDsForInnerPID(candidate) {
			if procStatusTgid(hostPID) == hostPID {
				return hostPID
			}
		}
	}
	if rec.Pid != 0 {
		return int(rec.Pid)
	}
	return int(rec.Tgid)
}

func procStatusTgid(pid int) int {
	if pid <= 0 {
		return 0
	}
	data, err := os.ReadFile(filepath.Join(procRootDir, strconv.Itoa(pid), "status"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Tgid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		tgid, err := strconv.Atoi(fields[1])
		if err != nil || tgid <= 0 {
			return 0
		}
		return tgid
	}
	return 0
}

func findHostPIDsForInnerPID(innerPID int) []int {
	if innerPID <= 0 {
		return nil
	}
	entries, err := os.ReadDir(procRootDir)
	if err != nil {
		return nil
	}
	var hosts []int
	for _, entry := range entries {
		if !entry.IsDir() || !isNumeric(entry.Name()) {
			continue
		}
		hostPID, err := strconv.Atoi(entry.Name())
		if err != nil || hostPID <= 0 {
			continue
		}
		data, err := os.ReadFile(filepath.Join(procRootDir, entry.Name(), "status"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "NSpid:") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				break
			}
			for i := 1; i < len(fields); i++ {
				nsPID, err := strconv.Atoi(fields[i])
				if err == nil && nsPID == innerPID {
					hosts = append(hosts, hostPID)
					break
				}
			}
			break
		}
	}
	return hosts
}

func procComm(pid int) string {
	if pid <= 0 {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(procRootDir, strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func procExeInode(pid int) (exeInode, bool) {
	if pid <= 0 {
		return exeInode{}, false
	}
	dev, ino, err := statInode(filepath.Join(procRootDir, strconv.Itoa(pid), "exe"))
	if err != nil {
		return exeInode{}, false
	}
	return exeInode{dev: dev, ino: ino}, true
}

// exeInode identifies a binary by device and inode for cross-PID matching.
type exeInode struct {
	dev uint64
	ino uint64
}

func isGoExecutable(path string) bool {
	_, err := buildinfo.ReadFile(path)
	return err == nil
}

func statInode(path string) (dev, ino uint64, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, fmt.Errorf("statInode(%q): %w", path, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("stat inode unavailable")
	}
	return uint64(st.Dev), st.Ino, nil
}
