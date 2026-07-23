package tracer

import (
	"debug/buildinfo"
	"errors"
	"fmt"
	"os"
	"syscall"
)

// goTLSInode identifies a binary inode for GoTLS layout caching (used by plaintext scope).
type goTLSInode struct {
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
