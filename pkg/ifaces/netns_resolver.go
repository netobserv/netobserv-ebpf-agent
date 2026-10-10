package ifaces

import (
	"fmt"
	"os"
	"runtime"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type NetnsResolver interface {
	getCookie(nsh netns.NsHandle) uint64
	getNetNS() ([]string, error)
}

type netnsResolverImpl struct {
	enableNetNSCookie bool
}

func NewNetnsResolver(enabled bool) NetnsResolver {
	return &netnsResolverImpl{enableNetNSCookie: enabled}
}

func NewDisabledResolver() NetnsResolver {
	return &netnsResolverImpl{enableNetNSCookie: false}
}

func (n *netnsResolverImpl) getNetNS() ([]string, error) {
	log := logrus.WithField("component", "ifaces.netnsResolverImpl")
	files, err := os.ReadDir(netnsVolume)
	if err != nil {
		log.Warningf("can't detect any network-namespaces err: %v [Ignore if the agent privileged flag is not set]", err)
		return nil, fmt.Errorf("failed to list network-namespaces: %w", err)
	}
	netns := []string{""}
	if len(files) == 0 {
		log.WithField("netns", files).Debug("empty network-namespaces list")
		return netns, nil
	}
	for _, f := range files {
		ns := f.Name()
		netns = append(netns, ns)
		log.WithFields(logrus.Fields{"netns": ns}).Debug("Detected network-namespace")
	}

	return netns, nil
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
		log.WithError(err).Warnf("failed to read netns cookie for %s; interface attribution may be degraded", key)
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
				log.WithError(err).Error("failed to restore netns after reading cookie")
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
