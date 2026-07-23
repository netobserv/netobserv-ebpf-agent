package tracer

import (
	"errors"
	"fmt"
)

// GoTLSFDLayout describes how to walk crypto/tls.Conn -> net.Conn -> socket fd.
type GoTLSFDLayout struct {
	ConnFieldOffset uintptr // offset of conn (iface) in crypto/tls.Conn
	NetFDOffset     uintptr // offset of fd *netFD in net.conn inside *net.TCPConn
	SysfdOffset     uintptr // offset of Sysfd int in internal/poll.FD
}

var gotlsFDLayoutByVersion = map[string]GoTLSFDLayout{
	"go1.22": {ConnFieldOffset: 0x00, NetFDOffset: 0x30, SysfdOffset: 0x10},
	"go1.21": {ConnFieldOffset: 0x00, NetFDOffset: 0x30, SysfdOffset: 0x10},
	"go1.20": {ConnFieldOffset: 0x00, NetFDOffset: 0x30, SysfdOffset: 0x10},
}

// ResolveGoTLSFDLayout returns memory offsets for reading a socket fd from *tls.Conn.
func ResolveGoTLSFDLayout(path string, goVersion string) (*GoTLSFDLayout, error) {
	if layout, ok := gotlsFDLayoutByVersion[majorMinorGoVersion(goVersion)]; ok {
		layoutCopy := layout
		return &layoutCopy, nil
	}
	return nil, fmt.Errorf("no GoTLS fd layout for %s in %q: %w", goVersion, path, errors.New("unsupported Go version"))
}

func majorMinorGoVersion(v string) string {
	if len(v) < 6 {
		return v
	}
	for i := 3; i < len(v); i++ {
		if v[i] == '.' && i+1 < len(v) && v[i+1] >= '0' && v[i+1] <= '9' {
			for j := i + 1; j < len(v); j++ {
				if v[j] == '.' {
					return v[:j]
				}
			}
			return v
		}
	}
	return v
}

func readGoTLSFdFromConn(pid int, connPtr uint64, layout *GoTLSFDLayout) (int, bool) {
	if pid <= 0 || connPtr == 0 || layout == nil {
		return 0, false
	}
	// conn is an interface: { *type, *data }
	dataPtr, ok := readProcessUint64(pid, uintptr(connPtr)+layout.ConnFieldOffset+8)
	if !ok || dataPtr == 0 {
		return 0, false
	}
	netFDPtr, ok := readProcessUint64(pid, uintptr(dataPtr)+layout.NetFDOffset)
	if !ok || netFDPtr == 0 {
		return 0, false
	}
	sysfd, ok := readProcessInt32(pid, uintptr(netFDPtr)+layout.SysfdOffset)
	if !ok || sysfd < 0 {
		return 0, false
	}
	return int(sysfd), true
}
