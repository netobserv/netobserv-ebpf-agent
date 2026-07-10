package tracer

import (
	"encoding/binary"
	"hash/fnv"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var pslog = logrus.WithField("component", "tracer.plaintext_scope")

// PlaintextScope applies PID scoping, 5-tuple enrichment, deduplication, and flow-filter matching.
type PlaintextScope struct {
	filters []*FilterConfig

	mu              sync.RWMutex
	allowedPIDs     map[int]struct{}
	pidScopeActive  bool
	flowFilterPorts map[uint16]struct{}

	peerIPs  []net.IP
	peerNets []*net.IPNet

	explicitPIDs map[int]struct{}

	dedupEnabled bool
	dedupWindow  time.Duration
	dedup        map[uint64]time.Time

	minBytes int

	connAffinity   map[connAffinityKey]string
	pidNetIPs      map[int][]net.IP
	gotlsFDLayouts map[binaryInodeKey]*GoTLSFDLayout

	stopCh chan struct{}
}

type binaryInodeKey struct {
	Dev uint64
	Ino uint64
}

type connAffinityKey struct {
	pid       int
	direction string
}

func NewPlaintextScope(
	filters []*FilterConfig,
	explicitPIDList string,
	dedupEnabled bool,
	dedupWindow time.Duration,
	minBytes int,
) *PlaintextScope {
	if dedupWindow <= 0 {
		dedupWindow = 500 * time.Millisecond
	}
	s := &PlaintextScope{
		filters:         filters,
		allowedPIDs:     map[int]struct{}{},
		flowFilterPorts: map[uint16]struct{}{},
		explicitPIDs:    parsePIDAllowlist(explicitPIDList),
		dedupEnabled:    dedupEnabled,
		dedupWindow:     dedupWindow,
		dedup:           map[uint64]time.Time{},
		connAffinity:    map[connAffinityKey]string{},
		pidNetIPs:       map[int][]net.IP{},
		gotlsFDLayouts:  map[binaryInodeKey]*GoTLSFDLayout{},
		minBytes:        minBytes,
		stopCh:          make(chan struct{}),
	}
	s.parseFilters()
	return s
}

func (s *PlaintextScope) Start() {
	s.Refresh()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.Refresh()
			}
		}
	}()
}

func (s *PlaintextScope) Close() {
	close(s.stopCh)
}

func (s *PlaintextScope) parseFilters() {
	for _, f := range s.filters {
		if f == nil {
			continue
		}
		if f.PeerIP != "" {
			if ip := net.ParseIP(f.PeerIP); ip != nil {
				s.peerIPs = append(s.peerIPs, ip)
				s.pidScopeActive = true
			}
		}
		if f.PeerCIDR != "" {
			_, n, err := net.ParseCIDR(f.PeerCIDR)
			if err == nil {
				s.peerNets = append(s.peerNets, n)
				s.pidScopeActive = true
			}
		}
		for _, port := range collectFilterPorts(f) {
			s.flowFilterPorts[port] = struct{}{}
		}
	}
	if len(s.explicitPIDs) > 0 {
		s.pidScopeActive = true
	}
}

func collectFilterPorts(f *FilterConfig) []uint16 {
	var ports []uint16
	add := func(p uint16) {
		if p > 0 {
			ports = append(ports, p)
		}
	}
	addFromInstr := func(instr intstr.IntOrString) {
		if instr.Type == intstr.Int {
			if instr.IntVal < 0 || instr.IntVal > 65535 {
				return
			}
			add(uint16(instr.IntVal))
			return
		}
		p1, p2, err := getPortsFromString(instr.String(), ",")
		if err == nil {
			add(p1)
			add(p2)
		}
	}
	addFromInstr(f.Port)
	addFromInstr(f.SourcePort)
	addFromInstr(f.DestinationPort)
	if f.Port.Type == intstr.String {
		start, end, err := getPortsFromString(f.Port.String(), "-")
		if err == nil {
			add(start)
			add(end)
		}
	}
	return ports
}

func (s *PlaintextScope) Refresh() {
	if !s.pidScopeActive {
		return
	}
	allowed := map[int]struct{}{}
	for pid := range s.explicitPIDs {
		allowed[pid] = struct{}{}
	}
	for _, ip := range s.peerIPs {
		for pid := range pidsWithIP(ip) {
			allowed[pid] = struct{}{}
		}
	}
	for _, n := range s.peerNets {
		for pid := range pidsWithIPInNet(n) {
			allowed[pid] = struct{}{}
		}
	}
	s.mu.Lock()
	// Keep previously discovered PIDs for the capture session. Socket tables only
	// show pod IPs on established/TIME_WAIT entries; a Go server listening on :: can
	// disappear from peer_ip scans between refresh ticks.
	for pid := range s.allowedPIDs {
		allowed[pid] = struct{}{}
	}
	s.allowedPIDs = allowed
	s.mu.Unlock()
	if len(allowed) > 0 {
		pslog.WithField("pids", len(allowed)).Debug("refreshed plaintext PID scope")
	} else if len(s.peerIPs) > 0 || len(s.peerNets) > 0 {
		pslog.Warn("plaintext PID scope is empty for configured peer_ip/peer_cidr (check hostPID, pod IP, and /proc/net/tcp6 on the target node)")
	}
}

func (s *PlaintextScope) PIDAllowed(pid int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.pidScopeActive {
		return true
	}
	if len(s.allowedPIDs) == 0 {
		return false
	}
	_, ok := s.allowedPIDs[pid]
	return ok
}

// PIDScoped reports whether pid is in the active peer_ip / peer_cidr / explicit PID allowlist.
func (s *PlaintextScope) PIDScoped(pid int) bool {
	if s == nil || !s.pidScopeActive {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.allowedPIDs[pid]
	return ok
}

// IsPIDScopeActive reports whether peer_ip, peer_cidr, or an explicit PID allowlist is configured.
func (s *PlaintextScope) IsPIDScopeActive() bool {
	if s == nil {
		return false
	}
	return s.pidScopeActive
}

// Process enriches and filters a plaintext record. Returns false when the record should be dropped.
func (s *PlaintextScope) Process(rec *model.PlaintextRecord) bool {
	if rec == nil {
		return false
	}
	pid, ok := s.resolveScopedPID(rec)
	if !ok {
		return false
	}
	if s.minBytes > 0 && len(rec.Data) < s.minBytes {
		return false
	}
	s.enrichFiveTuple(rec, pid)
	if !s.matchesFlowFilters(rec, pid) {
		return false
	}
	if s.dedupEnabled && s.isDuplicate(rec, pid) {
		return false
	}
	return true
}

func (s *PlaintextScope) resolveScopedPID(rec *model.PlaintextRecord) (int, bool) {
	raw := resolvePlaintextHostPID(rec)
	// kTLS events come from the kernel sk_msg path; PID allowlist discovery via
	// /proc is for uprobe targets and must not gate kernel-offloaded plaintext.
	if rec.TLSSource == model.TLSSourceKTLS {
		if raw > 0 {
			return raw, true
		}
		if host := s.scopedTargetPID(); host > 0 {
			return host, true
		}
		// sk_msg can report pid 0; still export when peer_ip/peer_cidr scopes capture.
		if s.pidScopeActive && (len(s.peerIPs) > 0 || len(s.peerNets) > 0) {
			return 0, true
		}
		if !s.pidScopeActive {
			return 0, true
		}
		return 0, false
	}
	if !s.pidScopeActive {
		return raw, raw > 0
	}
	if tgid := procStatusTgid(raw); tgid > 0 && s.PIDAllowed(tgid) {
		return tgid, true
	}
	if raw > 0 && s.PIDAllowed(raw) {
		return raw, true
	}
	if raw > 0 && s.pidMatchesPeerScope(raw) {
		s.admitPID(raw)
		return raw, true
	}
	if host := s.allowedPIDSharingExecutable(raw); host > 0 {
		return host, true
	}
	if host := s.scopedTargetPID(); host > 0 {
		return host, true
	}
	return 0, false
}

func (s *PlaintextScope) admitPID(pid int) {
	if pid <= 0 {
		return
	}
	s.mu.Lock()
	s.allowedPIDs[pid] = struct{}{}
	s.mu.Unlock()
}

// scopedTargetPID picks the allowed process that should own GoTLS plaintext events.
// peer_ip discovery often includes the pod pause process plus the workload container.
func (s *PlaintextScope) scopedTargetPID() int {
	s.mu.RLock()
	pids := make([]int, 0, len(s.allowedPIDs))
	for pid := range s.allowedPIDs {
		pids = append(pids, pid)
	}
	s.mu.RUnlock()
	if len(pids) == 0 {
		return 0
	}
	for _, pid := range pids {
		if pidMatchesFilterPorts(pid, s.flowFilterPorts) {
			return pid
		}
	}
	for _, pid := range pids {
		exePath := filepath.Join(procRootDir, strconv.Itoa(pid), "exe")
		if isGoExecutable(exePath) {
			return pid
		}
	}
	for _, pid := range pids {
		if comm := procComm(pid); comm != "" && comm != "pause" {
			return pid
		}
	}
	if len(pids) == 1 {
		return pids[0]
	}
	return 0
}

func (s *PlaintextScope) allowedPIDSharingExecutable(pid int) int {
	if pid <= 0 {
		return 0
	}
	exeInode, ok := procExeInode(pid)
	if !ok {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for allowedPID := range s.allowedPIDs {
		if allowed, ok := procExeInode(allowedPID); ok && allowed == exeInode {
			return allowedPID
		}
	}
	return 0
}

func (s *PlaintextScope) pidMatchesPeerScope(pid int) bool {
	for _, ip := range s.peerIPs {
		if pidHasIPInNetNS(pid, ip) {
			return true
		}
	}
	for _, n := range s.peerNets {
		if pidIPInNetNS(pid, n) {
			return true
		}
	}
	return false
}

func (s *PlaintextScope) RegisterGoTLSFDLayout(dev, ino uint64, layout *GoTLSFDLayout) {
	if s == nil || layout == nil || ino == 0 {
		return
	}
	s.mu.Lock()
	s.gotlsFDLayouts[binaryInodeKey{Dev: dev, Ino: ino}] = layout
	s.mu.Unlock()
}

func (s *PlaintextScope) enrichFiveTuple(rec *model.PlaintextRecord, pid int) {
	if rec != nil && rec.SrcAddr != "" && rec.DstAddr != "" && rec.SrcPort > 0 && rec.DstPort > 0 {
		if rec.Protocol == "" {
			rec.Protocol = "TCP"
		}
		return
	}
	if s.enrichFromSocketFD(rec, pid) {
		return
	}
	conns := s.connectionsForEnrichment(pid)
	if len(conns) == 0 {
		s.enrichFromFilterScope(rec)
		return
	}
	best := s.pickConnection(conns, rec.Direction, pid)
	if best == nil {
		s.enrichFromFilterScope(rec)
		return
	}
	rec.SrcAddr = best.localIP.String()
	rec.DstAddr = best.remoteIP.String()
	rec.SrcPort = best.localPort
	rec.DstPort = best.remotePort
	rec.Protocol = "TCP"
}

func (s *PlaintextScope) enrichFromSocketFD(rec *model.PlaintextRecord, pid int) bool {
	if rec == nil {
		return false
	}
	fd, ok := s.resolveSocketFD(rec, pid)
	if !ok || fd < 0 {
		return false
	}
	rec.SocketFd = int32(fd)
	inode, ok := socketInodeFromFD(pid, fd)
	if !ok {
		return false
	}
	conns := s.connectionsForEnrichment(pid)
	c := connectionByInode(conns, inode)
	if c == nil {
		return false
	}
	rec.SrcAddr = c.localIP.String()
	rec.DstAddr = c.remoteIP.String()
	rec.SrcPort = c.localPort
	rec.DstPort = c.remotePort
	rec.Protocol = "TCP"
	return true
}

func (s *PlaintextScope) resolveSocketFD(rec *model.PlaintextRecord, pid int) (int, bool) {
	if rec.SocketFd >= 0 {
		return int(rec.SocketFd), true
	}
	switch rec.TLSSource {
	case model.TLSSourceOpenSSL:
		if rec.ConnPtr != 0 {
			return readOpenSSLFdFromSSL(pid, rec.ConnPtr)
		}
	case model.TLSSourceGoTLS:
		if rec.ConnPtr != 0 {
			layout := s.goTLSLayoutForPID(pid)
			if layout != nil {
				return readGoTLSFdFromConn(pid, rec.ConnPtr, layout)
			}
		}
	}
	return 0, false
}

func (s *PlaintextScope) goTLSLayoutForPID(pid int) *GoTLSFDLayout {
	if pid <= 0 {
		return nil
	}
	key, ok := procExeInode(pid)
	if !ok {
		return nil
	}
	s.mu.RLock()
	layout := s.gotlsFDLayouts[binaryInodeKey{Dev: key.dev, Ino: key.ino}]
	s.mu.RUnlock()
	return layout
}

func (s *PlaintextScope) netnsIPs(pid int) []net.IP {
	if pid <= 0 {
		return nil
	}
	s.mu.RLock()
	if ips, ok := s.pidNetIPs[pid]; ok {
		s.mu.RUnlock()
		return ips
	}
	s.mu.RUnlock()
	ips := listInterfaceIPsInNetNS(pid)
	s.mu.Lock()
	s.pidNetIPs[pid] = ips
	s.mu.Unlock()
	return ips
}

func (s *PlaintextScope) pickConnection(conns []procTCPConn, direction string, pid int) *procTCPConn {
	netnsIPs := s.netnsIPs(pid)
	affinityKey := connAffinityKey{pid: pid, direction: direction}
	s.mu.RLock()
	preferred := s.connAffinity[affinityKey]
	s.mu.RUnlock()

	var best *procTCPConn
	bestScore := -1
	for i := range conns {
		c := &conns[i]
		if !isUsableProcTCPConn(c) {
			continue
		}
		score := scoreConnection(c, direction, s.flowFilterPorts, s.peerIPs, s.peerNets, netnsIPs)
		if preferred != "" && procConnKey(c) == preferred {
			score += 20
		}
		if score > bestScore {
			bestScore = score
			best = c
		}
	}
	if bestScore < 0 {
		return nil
	}
	s.mu.Lock()
	s.connAffinity[affinityKey] = procConnKey(best)
	s.mu.Unlock()
	return best
}

func procConnKey(c *procTCPConn) string {
	if c == nil {
		return ""
	}
	return c.localIP.String() + ":" + strconv.Itoa(int(c.localPort)) + "-" +
		c.remoteIP.String() + ":" + strconv.Itoa(int(c.remotePort))
}

// connectionsForEnrichment returns established TCP sockets for 5-tuple enrichment.
// kTLS sk_msg often reports pid 0; scan all scoped workload PIDs in that case.
func (s *PlaintextScope) connectionsForEnrichment(pid int) []procTCPConn {
	var pids []int
	if pid > 0 {
		pids = []int{pid}
	} else if target := s.scopedTargetPID(); target > 0 {
		pids = []int{target}
	} else {
		s.mu.RLock()
		pids = make([]int, 0, len(s.allowedPIDs))
		for scopedPID := range s.allowedPIDs {
			pids = append(pids, scopedPID)
		}
		s.mu.RUnlock()
		if len(pids) == 0 {
			pids = s.discoveryPIDsForFilters()
		}
	}
	if len(pids) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var all []procTCPConn
	for _, scopedPID := range pids {
		conns, err := readProcTCPConns(scopedPID)
		if err != nil {
			continue
		}
		for _, c := range filterUsableProcTCPConns(conns) {
			key := c.localIP.String() + ":" + strconv.Itoa(int(c.localPort)) + "-" +
				c.remoteIP.String() + ":" + strconv.Itoa(int(c.remotePort))
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			all = append(all, c)
		}
	}
	return all
}

func (s *PlaintextScope) discoveryPIDsForFilters() []int {
	seen := map[int]struct{}{}
	var pids []int
	add := func(set map[int]struct{}) {
		for pid := range set {
			if _, ok := seen[pid]; ok {
				continue
			}
			seen[pid] = struct{}{}
			pids = append(pids, pid)
		}
	}
	for _, ip := range s.peerIPs {
		add(pidsWithIP(ip))
	}
	for _, n := range s.peerNets {
		add(pidsWithIPInNet(n))
	}
	if len(s.flowFilterPorts) > 0 {
		add(pidsWithFilterPorts(s.flowFilterPorts))
	}
	return pids
}

func singleFilterPort(ports map[uint16]struct{}) uint16 {
	if len(ports) != 1 {
		return 0
	}
	for p := range ports {
		return p
	}
	return 0
}

func singlePeerIP(peerIPs []net.IP) net.IP {
	if len(peerIPs) != 1 {
		return nil
	}
	return peerIPs[0]
}

// applyWorkloadPartialTuple sets the workload pod endpoint on a plaintext record.
func applyWorkloadPartialTuple(rec *model.PlaintextRecord, peer net.IP, port uint16) {
	if rec == nil || peer == nil {
		return
	}
	rec.Protocol = "TCP"
	rec.SrcAddr = peer.String()
	if port > 0 {
		rec.SrcPort = port
	}
}

// enrichFromFilterScope fills a partial 5-tuple when /proc lookup fails but flow
// filters identify the workload endpoint (peer_ip and/or port; common for kTLS pid 0).
func (s *PlaintextScope) enrichFromFilterScope(rec *model.PlaintextRecord) {
	if rec == nil || (rec.SrcAddr != "" && rec.DstAddr != "") {
		return
	}
	peerIP := singlePeerIP(s.peerIPs)
	port := singleFilterPort(s.flowFilterPorts)
	if peerIP != nil {
		applyWorkloadPartialTuple(rec, peerIP, port)
		return
	}
	if port > 0 && rec.SrcPort == 0 && rec.DstPort == 0 {
		// Port-only partial: enough for export port filtering and CLI wire correlation.
		if rec.Direction == model.PlaintextDirectionRead {
			rec.DstPort = port
		} else {
			rec.SrcPort = port
		}
		rec.Protocol = "TCP"
	}
}

func pickConnection(
	conns []procTCPConn,
	direction string,
	ports map[uint16]struct{},
	peerIPs []net.IP,
	peerNets []*net.IPNet,
) *procTCPConn {
	var best *procTCPConn
	bestScore := -1
	for i := range conns {
		c := &conns[i]
		if !isUsableProcTCPConn(c) {
			continue
		}
		score := scoreConnection(c, direction, ports, peerIPs, peerNets, nil)
		if score > bestScore {
			bestScore = score
			best = c
		}
	}
	if bestScore < 0 {
		return nil
	}
	return best
}

func scoreConnection(
	c *procTCPConn,
	direction string,
	ports map[uint16]struct{},
	peerIPs []net.IP,
	peerNets []*net.IPNet,
	netnsIPs []net.IP,
) int {
	if !isUsableProcTCPConn(c) {
		return -1
	}
	if len(ports) > 0 && !connectionMatchesFilterPorts(c, ports) {
		return -1
	}
	score := connectionPeerScore(c, peerIPs, peerNets)
	if len(ports) > 0 {
		score += 2
	}
	if len(netnsIPs) > 0 && connectionUsesNetNSIPs(c, netnsIPs) {
		score += 8
	}
	score += connectionDirectionScore(direction, c)
	if score == 0 && len(ports) == 0 && len(peerIPs) == 0 && len(peerNets) == 0 {
		return 0
	}
	return score
}

func connectionMatchesFilterPorts(c *procTCPConn, ports map[uint16]struct{}) bool {
	for port := range ports {
		if c.localPort == port || c.remotePort == port {
			return true
		}
	}
	return false
}

func connectionPeerScore(c *procTCPConn, peerIPs []net.IP, peerNets []*net.IPNet) int {
	score := 0
	for _, ip := range peerIPs {
		if ipMatches(ip, c.localIP) || ipMatches(ip, c.remoteIP) {
			score += 4
		}
	}
	for _, n := range peerNets {
		if ipInNet(c.localIP, n) || ipInNet(c.remoteIP, n) {
			score += 4
		}
	}
	return score
}

func connectionDirectionScore(direction string, c *procTCPConn) int {
	if direction == model.PlaintextDirectionWrite && c.remotePort > 0 {
		return 1
	}
	if direction == model.PlaintextDirectionRead && c.localPort > 0 {
		return 1
	}
	return 0
}

func (s *PlaintextScope) matchesFlowFilters(rec *model.PlaintextRecord, pid int) bool {
	if rec.SrcAddr == "" && rec.DstAddr == "" {
		// Without a 5-tuple we cannot apply port or peer IP filters; wire PCA still
		// uses FLOW_FILTER_RULES. Dropping here silences OpenSSL capture when
		// --port is set but /proc enrichment has not filled addresses yet.
		return true
	}
	localIP := net.ParseIP(rec.SrcAddr)
	remoteIP := net.ParseIP(rec.DstAddr)
	if len(s.peerIPs) > 0 {
		matched := false
		for _, ip := range s.peerIPs {
			if ipMatches(ip, localIP) || ipMatches(ip, remoteIP) {
				matched = true
				break
			}
		}
		if !matched && s.PIDAllowed(pid) {
			matched = true
		}
		if !matched {
			return false
		}
	}
	if len(s.peerNets) > 0 {
		matched := false
		for _, n := range s.peerNets {
			if ipInNet(localIP, n) || ipInNet(remoteIP, n) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(s.flowFilterPorts) > 0 {
		matched := false
		for port := range s.flowFilterPorts {
			if rec.SrcPort == port || rec.DstPort == port {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func (s *PlaintextScope) isDuplicate(rec *model.PlaintextRecord, pid int) bool {
	key := dedupKey(rec, pid)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.dedup[key]; ok && now.Sub(t) < s.dedupWindow {
		return true
	}
	s.dedup[key] = now
	if len(s.dedup) > 4096 {
		for k, t := range s.dedup {
			if now.Sub(t) > s.dedupWindow {
				delete(s.dedup, k)
			}
		}
	}
	return false
}

func dedupKey(rec *model.PlaintextRecord, pid int) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(rec.Direction))
	_, _ = h.Write([]byte(strconv.Itoa(pid)))
	if rec.SrcAddr != "" || rec.DstAddr != "" {
		_, _ = h.Write([]byte(rec.SrcAddr))
		_, _ = h.Write([]byte(rec.DstAddr))
		var ports [4]byte
		binary.LittleEndian.PutUint16(ports[0:2], rec.SrcPort)
		binary.LittleEndian.PutUint16(ports[2:4], rec.DstPort)
		_, _ = h.Write(ports[:])
	} else if rec.ConnPtr != 0 {
		var conn [8]byte
		binary.LittleEndian.PutUint64(conn[:], rec.ConnPtr)
		_, _ = h.Write(conn[:])
	} else if rec.SocketFd >= 0 {
		_, _ = h.Write([]byte(strconv.Itoa(int(rec.SocketFd))))
	}
	preview := rec.Data
	if len(preview) > 64 {
		preview = preview[:64]
	}
	_, _ = h.Write(preview)
	return h.Sum64()
}

func parsePIDAllowlist(raw string) map[int]struct{} {
	out := map[int]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pid, err := strconv.Atoi(part)
		if err == nil && pid > 0 {
			out[pid] = struct{}{}
		}
	}
	return out
}
