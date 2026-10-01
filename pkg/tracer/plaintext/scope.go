package plaintext

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/attach"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// FilterConfig is an alias for attach.FilterConfig to avoid importing pkg/tracer.
type FilterConfig = attach.FilterConfig

var pslog = logrus.WithField("component", "plaintext.scope")

// Scope applies PID scoping, 5-tuple enrichment, deduplication, and flow-filter matching.
type Scope struct {
	filters []*FilterConfig

	mu              sync.RWMutex
	allowedPIDs     map[int]struct{}
	pidScopeActive  bool
	flowFilterPorts map[uint16]struct{}

	peerIPs  []net.IP
	peerNets []*net.IPNet

	explicitPIDs     map[int]struct{}
	processAllowlist map[string]struct{}

	dedupEnabled bool
	dedupWindow  time.Duration
	dedup        map[uint64]time.Time

	minBytes int

	stopCh chan struct{}
}

func NewScope(
	filters []*FilterConfig,
	explicitPIDList string,
	processAllowlist string,
	dedupEnabled bool,
	dedupWindow time.Duration,
	minBytes int,
) *Scope {
	if dedupWindow <= 0 {
		dedupWindow = 500 * time.Millisecond
	}
	s := &Scope{
		filters:          filters,
		allowedPIDs:      map[int]struct{}{},
		flowFilterPorts:  map[uint16]struct{}{},
		explicitPIDs:     parsePIDAllowlist(explicitPIDList),
		processAllowlist: parseProcessAllowlist(processAllowlist),
		dedupEnabled:     dedupEnabled,
		dedupWindow:      dedupWindow,
		dedup:            map[uint64]time.Time{},
		minBytes:         minBytes,
		stopCh:           make(chan struct{}),
	}
	s.parseFilters()
	return s
}

func (s *Scope) Start() {
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

func (s *Scope) Close() {
	close(s.stopCh)
}

func (s *Scope) parseFilters() {
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

func (s *Scope) Refresh() {
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

func (s *Scope) PIDAllowed(pid int) bool {
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
func (s *Scope) PIDScoped(pid int) bool {
	if s == nil || !s.pidScopeActive {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.allowedPIDs[pid]
	return ok
}

// IsPIDScopeActive reports whether peer_ip, peer_cidr, or an explicit PID allowlist is configured.
func (s *Scope) IsPIDScopeActive() bool {
	if s == nil {
		return false
	}
	return s.pidScopeActive
}

// Process enriches and filters a plaintext record. Returns false when the record should be dropped.
func (s *Scope) Process(rec *model.PlaintextRecord) bool {
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
	s.enrichFiveTuple(rec)
	if !s.matchesFlowFilters(rec, pid) {
		return false
	}
	if s.dedupEnabled && s.isDuplicate(rec, pid) {
		return false
	}
	return true
}

func (s *Scope) resolveScopedPID(rec *model.PlaintextRecord) (int, bool) {
	raw := resolvePlaintextHostPID(rec)
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
	// Before the best-effort remap, only attribute the event to a scoped PID sharing the
	// event's network namespace (i.e. the same pod). Replicas of one deployment scheduled
	// on a node share the libssl inode, so their uprobe fires for every replica; without
	// this guard a sibling replica's plaintext gets misattributed to the scoped pod. Only
	// decide here when we have positive netns evidence; otherwise fall through so
	// single-pod captures with unresolved namespaces keep working.
	if host, decided := s.scopedTargetPIDForEventNetNS(raw); decided {
		if host > 0 {
			return host, true
		}
		return 0, false
	}
	if host := s.scopedTargetPID(); host > 0 {
		return host, true
	}
	return 0, false
}

func (s *Scope) admitPID(pid int) {
	if pid <= 0 {
		return
	}
	s.mu.Lock()
	s.allowedPIDs[pid] = struct{}{}
	s.mu.Unlock()
}

// scopedTargetPID picks the allowed process that should own plaintext events.
// peer_ip discovery often includes the pod pause process plus the workload container.
func (s *Scope) scopedTargetPID() int {
	return s.pickTargetPID(s.allowedPIDsSnapshot())
}

// scopedTargetPIDForEventNetNS picks the scoped process owning the event, restricted to
// PIDs sharing rawPID's network namespace so events are never attributed across pods.
// decided is false when there is no netns evidence (rawPID or every scoped PID has an
// undeterminable namespace); the caller then falls back to the best-effort target.
// When decided is true and pid is 0, the event belongs to a different pod and is dropped.
func (s *Scope) scopedTargetPIDForEventNetNS(rawPID int) (pid int, decided bool) {
	if rawPID <= 0 {
		return 0, false
	}
	if _, known := procNetNSID(rawPID); !known {
		return 0, false
	}
	sameNS := make([]int, 0)
	sawKnownNS := false
	for _, candidate := range s.allowedPIDsSnapshot() {
		same, known := sameNetNS(rawPID, candidate)
		if !known {
			continue
		}
		sawKnownNS = true
		if same {
			sameNS = append(sameNS, candidate)
		}
	}
	if len(sameNS) > 0 {
		return s.pickTargetPID(sameNS), true
	}
	// Positive evidence: scoped PIDs exist with resolvable namespaces and none match the
	// event's namespace, so this plaintext belongs to a different pod. Drop it.
	if sawKnownNS {
		return 0, true
	}
	return 0, false
}

func (s *Scope) allowedPIDsSnapshot() []int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pids := make([]int, 0, len(s.allowedPIDs))
	for pid := range s.allowedPIDs {
		pids = append(pids, pid)
	}
	return pids
}

func (s *Scope) pickTargetPID(pids []int) int {
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

func (s *Scope) allowedPIDSharingExecutable(pid int) int {
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
		if allowed, ok := procExeInode(allowedPID); !ok || allowed != exeInode {
			continue
		}
		// Replicas of one deployment share the executable inode but run in separate
		// network namespaces. Only remap within the same netns (same pod) so a hooked
		// sibling replica's plaintext is not misattributed to the scoped pod.
		if same, known := sameNetNS(pid, allowedPID); known && !same {
			continue
		}
		return allowedPID
	}
	return 0
}

func (s *Scope) pidMatchesPeerScope(pid int) bool {
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

func (s *Scope) enrichFiveTuple(rec *model.PlaintextRecord) {
	if rec != nil && rec.SrcAddr != "" && rec.DstAddr != "" && rec.SrcPort > 0 && rec.DstPort > 0 {
		if rec.Protocol == "" {
			rec.Protocol = "TCP"
		}
		return
	}
	// A queued event's SSL pointer, fd and /proc socket table may already
	// belong to another connection. Never turn that snapshot into identity.
	s.enrichFromFilterScope(rec)
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
// filters identify the workload endpoint (peer_ip and/or port).
func (s *Scope) enrichFromFilterScope(rec *model.PlaintextRecord) {
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

func (s *Scope) matchesFlowFilters(rec *model.PlaintextRecord, pid int) bool {
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

func (s *Scope) isDuplicate(rec *model.PlaintextRecord, pid int) bool {
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

func parseProcessAllowlist(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out[part] = struct{}{}
		}
	}
	return out
}

func (s *Scope) HasProcessAllowlist() bool {
	return len(s.processAllowlist) > 0
}

func (s *Scope) ProcessAllowlisted(comm string) bool {
	if len(s.processAllowlist) == 0 {
		return true
	}
	_, ok := s.processAllowlist[comm]
	return ok
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

func getPortsFromString(s, sep string) (uint16, uint16, error) {
	ps := strings.SplitN(s, sep, 2)
	if len(ps) != 2 {
		return 0, 0, fmt.Errorf("invalid ports range. Expected two integers separated by %s but found %s", sep, s)
	}
	startPort, err := strconv.ParseUint(ps[0], 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start port number %w", err)
	}
	endPort, err := strconv.ParseUint(ps[1], 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end port number %w", err)
	}
	if sep == "-" && startPort > endPort {
		return 0, 0, fmt.Errorf("invalid port range. Start port is greater than end port")
	}
	return uint16(startPort), uint16(endPort), nil
}
