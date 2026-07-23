package tracer

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

// readOpenSSLFdFromSSL reads the socket fd from an OpenSSL SSL* in process memory.
// Offsets match OpenSSL 1.1.1 / 3.x BIO socket layout on little-endian 64-bit.
func readOpenSSLFdFromSSL(pid int, sslPtr uint64) (int, bool) {
	if pid <= 0 || sslPtr == 0 {
		return 0, false
	}
	const (
		sslRBIOOffset = 0x10
		bioNumOffset  = 0x30
	)
	rbio, ok := readProcessUint64(pid, uintptr(sslPtr)+sslRBIOOffset)
	if !ok || rbio == 0 {
		return 0, false
	}
	num, ok := readProcessInt32(pid, uintptr(rbio)+bioNumOffset)
	if !ok || num < 0 {
		return 0, false
	}
	return int(num), true
}

func readProcessUint64(pid int, addr uintptr) (uint64, bool) {
	b, ok := readProcessMemory(pid, addr, 8)
	if !ok {
		return 0, false
	}
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56, true
}

func readProcessInt32(pid int, addr uintptr) (int32, bool) {
	b, ok := readProcessMemory(pid, addr, 4)
	if !ok {
		return 0, false
	}
	v := int32(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24)
	return v, true
}

func readProcessMemory(pid int, addr uintptr, size int) ([]byte, bool) {
	if pid <= 0 || addr == 0 || size <= 0 {
		return nil, false
	}
	f, err := os.Open(filepath.Join(procRootDir, strconv.Itoa(pid), "mem"))
	if err != nil {
		return nil, false
	}
	defer f.Close()

	buf := make([]byte, size)
	n, err := f.ReadAt(buf, int64(addr))
	if err != nil || n != size {
		return nil, false
	}
	return buf, true
}
