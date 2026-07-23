package tracer

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
)

// opensslHostRoot is where host /usr, /lib and /lib64 are mounted in the agent pod.
var opensslHostRoot = "/host"

// procRootDir is the procfs root used for discovery (overridable in tests).
var procRootDir = "/proc"

var olog = logrus.WithField("component", "tracer.openssl")

type inodeKey struct {
	dev uint64
	ino uint64
}

// opensslAttacher discovers libssl.so paths from /proc and attaches uprobes.
type opensslAttacher struct {
	writeProg     *ebpf.Program
	readEntryProg *ebpf.Program
	readRetProg   *ebpf.Program
	setFdProg     *ebpf.Program
	scope         *PlaintextScope
	links         []link.Link
	attached      map[string]bool
	mu            sync.Mutex
	stopCh        chan struct{}
}

func newOpenSSLAttacher(writeProg, readEntryProg, readRetProg, setFdProg *ebpf.Program, scope *PlaintextScope) *opensslAttacher {
	return &opensslAttacher{
		writeProg:     writeProg,
		readEntryProg: readEntryProg,
		readRetProg:   readRetProg,
		setFdProg:     setFdProg,
		scope:         scope,
		attached:      map[string]bool{},
		stopCh:        make(chan struct{}),
	}
}

func (a *opensslAttacher) Start(defaultPath string) {
	olog.Infof("starting OpenSSL uprobe scanner (OPENSSL_PATH=%s)", defaultPath)
	a.scanOnce()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-a.stopCh:
				return
			case <-ticker.C:
				a.scanOnce()
			}
		}
	}()
}

func (a *opensslAttacher) Close() {
	close(a.stopCh)
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, l := range a.links {
		_ = l.Close()
	}
	a.links = nil
	a.attached = map[string]bool{}
}

func (a *opensslAttacher) scanOnce() {
	paths := discoverLibSSLAttachPaths(a.pidAllowed, a.scope)
	if len(paths) == 0 {
		olog.Warn("no libssl.so libraries discovered; TLS plaintext capture needs hostPID, host /usr/lib mounts, and workloads using dynamic OpenSSL")
		return
	}
	before := len(a.attached)
	for _, p := range paths {
		a.attachToLibrary(p)
	}
	if len(a.attached) > before {
		olog.Infof("OpenSSL uprobe attachment count is now %d", len(a.attached))
	}
}

func discoverLibSSLAttachPaths(pidAllowed func(int) bool, scope *PlaintextScope) []string {
	seenInode := map[inodeKey]bool{}
	var paths []string
	addPath := func(p string) {
		paths = appendUniqueLibSSLPath(paths, seenInode, p)
	}

	// Only attach per-container libssl copies under /proc/<pid>/root. Attaching the
	// host default OPENSSL_PATH hooks every process on the node that loads that library.
	selfPID := os.Getpid()
	entries, err := os.ReadDir(procRootDir)
	if err != nil {
		return paths
	}
	for _, entry := range entries {
		pidStr, ok := eligibleProcPIDForLibSSL(filepath.Join(procRootDir, entry.Name()), entry, nil, selfPID, pidAllowed, scope)
		if !ok {
			continue
		}
		collectLibSSLPathsFromMaps(pidStr, addPath)
	}

	return paths
}

func appendUniqueLibSSLPath(paths []string, seenInode map[inodeKey]bool, p string) []string {
	if p == "" {
		return paths
	}
	info, err := os.Stat(p)
	if err != nil || info.IsDir() {
		return paths
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return paths
	}
	key := inodeKey{dev: uint64(st.Dev), ino: st.Ino}
	if seenInode[key] {
		return paths
	}
	seenInode[key] = true
	return append(paths, p)
}

func eligibleProcPIDForLibSSL(
	path string,
	d fs.DirEntry,
	err error,
	selfPID int,
	pidAllowed func(int) bool,
	scope *PlaintextScope,
) (string, bool) {
	if err != nil || !d.IsDir() {
		return "", false
	}
	pidStr := filepath.Base(path)
	if pidStr == filepath.Base(procRootDir) || !isNumeric(pidStr) {
		return "", false
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid == selfPID {
		return "", false
	}
	if pidAllowed != nil && !pidAllowed(pid) {
		return "", false
	}
	if isPlaintextCaptureExcludedPID(pidStr, scope) {
		return "", false
	}
	return pidStr, true
}

func collectLibSSLPathsFromMaps(pidStr string, addPath func(string)) {
	mapsFile := filepath.Join(procRootDir, pidStr, "maps")
	data, err := os.ReadFile(mapsFile)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		libPath := fields[len(fields)-1]
		if !strings.Contains(libPath, "libssl.so") || strings.HasPrefix(libPath, "/dev/") {
			continue
		}
		if !filepath.IsAbs(libPath) {
			continue
		}
		addPath(filepath.Join(procRootDir, pidStr, "root", libPath))
	}
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func (a *opensslAttacher) attachToLibrary(attachPath string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.attached[attachPath] {
		return
	}

	exe, err := link.OpenExecutable(attachPath)
	if err != nil {
		olog.WithError(err).Warnf("cannot open libssl at %s", attachPath)
		return
	}

	attached := false
	if a.setFdProg != nil {
		l, err := exe.Uprobe("SSL_set_fd", a.setFdProg, nil)
		if err != nil {
			olog.WithError(err).Debugf("SSL_set_fd uprobe failed on %s", attachPath)
		} else {
			a.links = append(a.links, l)
			attached = true
		}
	}

	if a.writeProg != nil {
		l, err := exe.Uprobe("SSL_write", a.writeProg, nil)
		if err != nil {
			olog.WithError(err).Warnf("SSL_write uprobe failed on %s", attachPath)
		} else {
			a.links = append(a.links, l)
			olog.Infof("attached SSL_write uprobe to %s", attachPath)
			attached = true
		}
	}

	if a.readEntryProg != nil && a.readRetProg != nil {
		entry, err := exe.Uprobe("SSL_read", a.readEntryProg, nil)
		if err != nil {
			olog.WithError(err).Warnf("SSL_read entry uprobe failed on %s", attachPath)
		} else {
			a.links = append(a.links, entry)
			ret, err := exe.Uretprobe("SSL_read", a.readRetProg, nil)
			if err != nil {
				olog.WithError(err).Warnf("SSL_read uretprobe failed on %s", attachPath)
			} else {
				a.links = append(a.links, ret)
				olog.Infof("attached SSL_read uretprobe to %s", attachPath)
				attached = true
			}
		}
	}

	if attached {
		a.attached[attachPath] = true
	}
}

// resolveHostLibSSLPath maps host library paths into the agent mount namespace.
func resolveHostLibSSLPath(libPath string) string {
	if libPath == "" {
		return libPath
	}
	candidates := []string{libPath}
	if filepath.IsAbs(libPath) {
		candidates = append([]string{filepath.Join(opensslHostRoot, libPath)}, candidates...)
	}
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate
		}
	}
	return libPath
}

// resolveOpenSSLLibPath is kept for tests and backwards compatibility.
func resolveOpenSSLLibPath(libPath string) string {
	return resolveHostLibSSLPath(libPath)
}

func attachOpenSSLUprobes(cfg *FlowFetcherConfig, writeProg, readEntryProg, readRetProg, setFdProg *ebpf.Program) (*opensslAttacher, error) {
	if writeProg == nil && readEntryProg == nil && readRetProg == nil && setFdProg == nil {
		return nil, fmt.Errorf("no OpenSSL programs loaded")
	}
	attacher := newOpenSSLAttacher(writeProg, readEntryProg, readRetProg, setFdProg, cfg.PlaintextScope)
	attacher.Start(cfg.OpenSSLPath)
	return attacher, nil
}

func (a *opensslAttacher) pidAllowed(pid int) bool {
	if a.scope == nil {
		return true
	}
	return a.scope.PIDAllowed(pid)
}
