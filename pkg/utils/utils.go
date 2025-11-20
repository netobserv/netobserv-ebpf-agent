package utils //nolint:revive

import (
	"fmt"
	"net"
)

// GetSocket returns socket string in the correct format based on address family
func GetSocket(hostIP string, hostPort int) string {
	socket := fmt.Sprintf("%s:%d", hostIP, hostPort)
	ipAddr := net.ParseIP(hostIP)
	if ipAddr != nil && ipAddr.To4() == nil {
		socket = fmt.Sprintf("[%s]:%d", hostIP, hostPort)
	}
	return socket
}

// DNSRawNameToDotted parses a label-encoded DNS QNAME (raw bytes copied from kernel)
// into a dotted string. Stops on NUL, compression pointer, or bounds.
func DNSRawNameToDotted(rawI8 []int8) string {
	// Convert to byte slice up to first NUL
	b := make([]byte, 0, len(rawI8))
	for i := 0; i < len(rawI8); i++ {
		if rawI8[i] == 0 { // NUL terminator placed in kernel copy
			break
		}
		b = append(b, byte(rawI8[i]))
	}
	if len(b) == 0 {
		return ""
	}
	out := make([]byte, 0, len(b))
	i := 0
	first := true
	for i < len(b) {
		l := int(b[i])
		if l == 0 {
			break
		}
		// Stop on compression pointer (0xC0xx) since we didn't follow it in kernel
		// l is the length byte of a DNS label.
		// 0xC0 in binary is 11000000.
		// The bitwise AND l & 0xC0 isolates the top two bits of l.
		// If the result equals 0xC0, it indicates a compression pointer.
		if (l & 0xC0) == 0xC0 {
			break
		}
		i++
		if i+l > len(b) {
			break
		}
		if !first {
			out = append(out, '.')
		}
		first = false
		out = append(out, b[i:i+l]...)
		i += l
	}
	return string(out)
}
