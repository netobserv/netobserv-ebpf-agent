package plaintext

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// socketInodeFromFD resolves the kernel socket inode for an open fd via /proc/<pid>/fd/<n>.
func socketInodeFromFD(pid int, fd int) (uint64, bool) {
	if pid <= 0 || fd < 0 {
		return 0, false
	}
	link, err := os.Readlink(filepath.Join(procRootDir, strconv.Itoa(pid), "fd", strconv.Itoa(fd)))
	if err != nil {
		return 0, false
	}
	if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
		return 0, false
	}
	inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
	if err != nil || inode == 0 {
		return 0, false
	}
	return inode, true
}

func connectionByInode(conns []procTCPConn, inode uint64) *procTCPConn {
	if inode == 0 {
		return nil
	}
	for i := range conns {
		if conns[i].inode == inode {
			return &conns[i]
		}
	}
	return nil
}
