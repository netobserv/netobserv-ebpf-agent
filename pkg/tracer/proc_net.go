package tracer

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type procTCPConn struct {
	localIP    net.IP
	localPort  uint16
	remoteIP   net.IP
	remotePort uint16
	state      uint8
	inode      uint64
}

const procTCPStateEstablished = 0x01

func readProcTCPConns(pid int) ([]procTCPConn, error) {
	var out []procTCPConn
	for _, name := range []string{"tcp", "tcp6"} {
		path := filepath.Join(procRootDir, strconv.Itoa(pid), "net", name)
		conns, err := parseProcNetFile(path, name == "tcp6")
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		out = append(out, conns...)
	}
	return out, nil
}

func parseProcNetFile(path string, ipv6 bool) ([]procTCPConn, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	var conns []procTCPConn
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		if len(fields) < 4 {
			continue
		}
		state64, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			continue
		}
		var inode uint64
		if len(fields) >= 10 {
			inode, _ = strconv.ParseUint(fields[9], 10, 64)
		}
		localIP, localPort, err := parseProcNetAddr(fields[1], ipv6)
		if err != nil {
			continue
		}
		remoteIP, remotePort, err := parseProcNetAddr(fields[2], ipv6)
		if err != nil {
			continue
		}
		conns = append(conns, procTCPConn{
			localIP:    localIP,
			localPort:  localPort,
			remoteIP:   remoteIP,
			remotePort: remotePort,
			state:      uint8(state64),
			inode:      inode,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning %s: %w", path, err)
	}
	return conns, nil
}

func parseProcNetAddr(field string, ipv6 bool) (net.IP, uint16, error) {
	parts := strings.Split(field, ":")
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("invalid proc net address %q", field)
	}
	port64, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return nil, 0, err
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, 0, err
	}
	if ipv6 {
		if len(raw) != 16 {
			return nil, 0, fmt.Errorf("invalid ipv6 address length %d", len(raw))
		}
		return procNetIPFromRaw(raw), uint16(port64), nil
	}
	if len(raw) != 4 {
		return nil, 0, fmt.Errorf("invalid ipv4 address length %d", len(raw))
	}
	// /proc/net/tcp stores IPv4 addresses in little-endian.
	ip := net.IPv4(raw[3], raw[2], raw[1], raw[0])
	return ip, uint16(port64), nil
}

// procNetIPFromRaw converts a 16-byte /proc/net/tcp6 address to net.IP.
// IPv4 sockets use IPv6 API; the address is encoded with a ::ffff prefix and
// the IPv4 address in the last four bytes (little-endian).
func procNetIPFromRaw(raw []byte) net.IP {
	if v4, ok := procTCP6IPv4Suffix(raw); ok {
		return v4
	}
	return net.IP(raw)
}

func procTCP6IPv4Suffix(raw []byte) (net.IP, bool) {
	if len(raw) != 16 {
		return nil, false
	}
	for i := 0; i < 8; i++ {
		if raw[i] != 0 {
			return nil, false
		}
	}
	mid := uint32(raw[8])<<24 | uint32(raw[9])<<16 | uint32(raw[10])<<8 | uint32(raw[11])
	switch mid {
	case 0, 0x0000ffff, 0xffff0000:
		return net.IPv4(raw[15], raw[14], raw[13], raw[12]), true
	default:
		return nil, false
	}
}

func pidsWithIP(peer net.IP) map[int]struct{} {
	result := map[int]struct{}{}
	entries, err := os.ReadDir(procRootDir)
	if err != nil {
		return result
	}
	for _, entry := range entries {
		if !entry.IsDir() || !isNumeric(entry.Name()) {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		conns, err := readProcTCPConns(pid)
		if err != nil {
			continue
		}
		for _, c := range conns {
			if ipMatches(peer, c.localIP) || ipMatches(peer, c.remoteIP) {
				result[pid] = struct{}{}
				break
			}
		}
		if _, ok := result[pid]; !ok && pidHasIPInNetNS(pid, peer) {
			result[pid] = struct{}{}
		}
	}
	return result
}

func pidHasIPInNetNS(pid int, peer net.IP) bool {
	if peer == nil {
		return false
	}
	for _, ip := range listInterfaceIPsInNetNS(pid) {
		if ipMatches(ip, peer) {
			return true
		}
	}
	return false
}

func listInterfaceIPsInNetNS(pid int) []net.IP {
	if pid <= 0 {
		return nil
	}
	nsPath := filepath.Join(procRootDir, strconv.Itoa(pid), "ns", "net")
	ns, err := netns.GetFromPath(nsPath)
	if err != nil {
		return nil
	}
	defer ns.Close()

	handle, err := netlink.NewHandleAt(ns)
	if err != nil {
		return nil
	}
	defer handle.Close()

	var ips []net.IP
	links, err := handle.LinkList()
	if err != nil {
		return nil
	}
	for _, link := range links {
		addrs, err := handle.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := normalizeProcIP(addr.IP)
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			ips = append(ips, ip)
		}
	}
	return ips
}

func connectionUsesNetNSIPs(c *procTCPConn, netnsIPs []net.IP) bool {
	if c == nil {
		return false
	}
	for _, ip := range netnsIPs {
		if ipMatches(ip, c.localIP) || ipMatches(ip, c.remoteIP) {
			return true
		}
	}
	return false
}

func pidsWithIPInNet(peerNet *net.IPNet) map[int]struct{} {
	result := map[int]struct{}{}
	entries, err := os.ReadDir(procRootDir)
	if err != nil {
		return result
	}
	for _, entry := range entries {
		if !entry.IsDir() || !isNumeric(entry.Name()) {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		conns, err := readProcTCPConns(pid)
		if err != nil {
			continue
		}
		for _, c := range conns {
			if ipInNet(c.localIP, peerNet) || ipInNet(c.remoteIP, peerNet) {
				result[pid] = struct{}{}
				break
			}
		}
		if _, ok := result[pid]; !ok && pidIPInNetNS(pid, peerNet) {
			result[pid] = struct{}{}
		}
	}
	return result
}

func pidIPInNetNS(pid int, peerNet *net.IPNet) bool {
	if peerNet == nil {
		return false
	}
	nsPath := filepath.Join(procRootDir, strconv.Itoa(pid), "ns", "net")
	ns, err := netns.GetFromPath(nsPath)
	if err != nil {
		return false
	}
	defer ns.Close()

	handle, err := netlink.NewHandleAt(ns)
	if err != nil {
		return false
	}
	defer handle.Close()

	links, err := handle.LinkList()
	if err != nil {
		return false
	}
	for _, link := range links {
		addrs, err := handle.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipInNet(addr.IP, peerNet) {
				return true
			}
		}
	}
	return false
}

func ipMatches(ip, target net.IP) bool {
	if ip == nil || target == nil {
		return false
	}
	a := normalizeProcIP(ip)
	b := normalizeProcIP(target)
	if a != nil && b != nil {
		return a.Equal(b)
	}
	return ip.Equal(target)
}

func ipInNet(ip net.IP, n *net.IPNet) bool {
	if ip == nil || n == nil {
		return false
	}
	if v4 := normalizeProcIP(ip); v4 != nil {
		if _, bits := n.Mask.Size(); bits == 32 {
			return n.Contains(v4)
		}
	}
	return n.Contains(ip)
}

// normalizeProcIP maps IPv4-in-IPv6 addresses from /proc/net/tcp6 to IPv4.
func normalizeProcIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

func isUsableProcTCPConn(c *procTCPConn) bool {
	if c == nil {
		return false
	}
	if c.state != procTCPStateEstablished {
		return false
	}
	return isUsableProcIP(c.localIP) && isUsableProcIP(c.remoteIP)
}

func isUsableProcIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() {
		return false
	}
	return !ip.Equal(net.IPv4zero) && !ip.Equal(net.IPv6zero)
}

func pidMatchesFilterPorts(pid int, ports map[uint16]struct{}) bool {
	if pid <= 0 || len(ports) == 0 {
		return false
	}
	conns, err := readProcTCPConns(pid)
	if err != nil {
		return false
	}
	for i := range conns {
		c := &conns[i]
		for port := range ports {
			if c.localPort == port || c.remotePort == port {
				return true
			}
		}
	}
	return false
}

// pidsWithFilterPorts returns host PIDs with an established TCP socket using a filtered port.
func pidsWithFilterPorts(ports map[uint16]struct{}) map[int]struct{} {
	result := map[int]struct{}{}
	if len(ports) == 0 {
		return result
	}
	entries, err := os.ReadDir(procRootDir)
	if err != nil {
		return result
	}
	for _, entry := range entries {
		if !entry.IsDir() || !isNumeric(entry.Name()) {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if pidMatchesFilterPorts(pid, ports) {
			result[pid] = struct{}{}
		}
	}
	return result
}

func filterUsableProcTCPConns(conns []procTCPConn) []procTCPConn {
	out := make([]procTCPConn, 0, len(conns))
	for i := range conns {
		if isUsableProcTCPConn(&conns[i]) {
			out = append(out, conns[i])
		}
	}
	return out
}
