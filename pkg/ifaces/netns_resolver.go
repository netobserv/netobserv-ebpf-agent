package ifaces

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const defaultNetnsPath = "/var/run/netns"

var rzlog = logrus.WithField("component", "ifaces.NetnsResolver")

type NetnsResolver interface {
	getNetNSPath() string
	listNetNS() ([]string, error)
	isHostNSAlias(string) bool
	getHandle(string) (netns.NsHandle, error)
	getCookie(netns.NsHandle) uint64
}

type netnsResolverImpl struct {
	enableNetNSCookie bool
	netnsPath         string
	hostNetnsID       string
}

func NewNetnsResolver(netnsEnabled, cookiesEnabled bool) NetnsResolver {
	if !netnsEnabled {
		return NewDisabledResolver()
	}

	r := &netnsResolverImpl{netnsPath: defaultNetnsPath, enableNetNSCookie: cookiesEnabled}
	// Host alias dedup: get the host netns ID
	handle, err := netns.Get()
	if err != nil {
		rzlog.WithFields(logrus.Fields{
			"error": err,
		}).Warn("error while reading host netns for alias deduplication; turning off alias dedup optimization")
		return r
	}
	defer handle.Close()
	r.hostNetnsID = handle.UniqueId()
	return r
}

func NewDisabledResolver() NetnsResolver {
	// All disabled
	return &netnsResolverImpl{}
}

func (n *netnsResolverImpl) getNetNSPath() string {
	return n.netnsPath
}

func (n *netnsResolverImpl) listNetNS() ([]string, error) {
	// Empty string stands for default netns
	netns := []string{""}

	if n.netnsPath == "" {
		// No netns
		return netns, nil
	}

	files, err := os.ReadDir(n.netnsPath)
	if err != nil {
		rzlog.Warningf("can't detect any network namespaces err: %v [Ignore if the agent privileged flag is not set]", err)
		return nil, fmt.Errorf("failed to list network namespaces: %w", err)
	}

	if len(files) == 0 {
		rzlog.WithField("netns", files).Debug("empty network namespaces list")
		return netns, nil
	}

	for _, f := range files {
		ns := f.Name()
		if !n.isHostNSAlias(ns) {
			netns = append(netns, ns)
			rzlog.WithFields(logrus.Fields{"netns": ns}).Debug("Detected network namespace")
		}
	}

	return netns, nil
}

// isHostNSAlias reports whether netns entry is just another name for the namespace the agent already watches as ""
func (n *netnsResolverImpl) isHostNSAlias(ns string) bool {
	if ns == "" || n.hostNetnsID == "" {
		return false
	}
	handle, err := n.getHandle(ns)
	if err != nil {
		rzlog.WithFields(logrus.Fields{
			"netns": ns,
			"error": err,
		}).Debug("cannot read netns for alias deduplication; treating like it's not an alias")
		return false
	}
	defer handle.Close()
	if handle.UniqueId() != n.hostNetnsID {
		return false
	}
	rzlog.WithFields(logrus.Fields{
		"netns":   ns,
		"netnsID": n.hostNetnsID,
	}).Debug("skipping netns alias, already watched")
	return true
}

func (n *netnsResolverImpl) getHandle(ns string) (netns.NsHandle, error) {
	if ns == "" || n.netnsPath == "" {
		return netns.None(), nil
	}
	return netns.GetFromPath(filepath.Join(n.netnsPath, ns))
}

// getCookie returns the kernel netns cookie for the given handle (0 when disabled or
// on error), matching bpf_get_netns_cookie on the eBPF side. Results are cached per namespace.
func (n *netnsResolverImpl) getCookie(nsh netns.NsHandle) uint64 {
	if !n.enableNetNSCookie {
		return 0
	}
	cookie, err := readNSCookie(nsh)
	if err != nil {
		key := "host"
		if nsh.IsOpen() {
			key = nsh.UniqueId()
		}
		rzlog.WithError(err).Warnf("failed to read netns cookie for %s; interface attribution may be degraded", key)
		return 0
	}
	return cookie
}

func readNSCookie(nsh netns.NsHandle) (uint64, error) {
	runtime.LockOSThread()
	unlock := true
	defer func() {
		if unlock {
			runtime.UnlockOSThread()
		}
	}()

	// For a specific namespace, enter it on the locked thread and restore afterwards.
	// netns.None() means "current thread's namespace" (the host netns for the agent).
	if nsh.IsOpen() {
		orig, err := netns.Get()
		if err != nil {
			return 0, fmt.Errorf("failed to get current netns: %w", err)
		}
		defer func() {
			if err := netns.Set(orig); err != nil {
				unlock = false
				rzlog.WithError(err).Error("failed to restore netns after reading cookie")
			}
			orig.Close()
		}()
		if err := netns.Set(nsh); err != nil {
			return 0, fmt.Errorf("failed to enter netns: %w", err)
		}
	}

	// Any socket carries its namespace's cookie via SO_NETNS_COOKIE; the value is identical
	// to bpf_get_netns_cookie. AF_UNIX/SOCK_DGRAM is always available inside a namespace.
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to create socket: %w", err)
	}
	defer unix.Close(fd)
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil {
		return 0, fmt.Errorf("failed to get SO_NETNS_COOKIE: %w", err)
	}
	return cookie, nil
}
