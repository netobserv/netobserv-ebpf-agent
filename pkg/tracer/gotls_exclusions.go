package tracer

import (
	"os"
	"path/filepath"
	"strings"
)

func normalizeExePath(path string) string {
	return strings.TrimSuffix(path, " (deleted)")
}

func readProcComm(pid string) string {
	data, err := os.ReadFile(filepath.Join(procRootDir, pid, "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func resolveProcExe(pid, exePath string) (resolved, comm string) {
	comm = readProcComm(pid)
	resolved, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		resolved = exePath
	}
	return normalizeExePath(resolved), comm
}
