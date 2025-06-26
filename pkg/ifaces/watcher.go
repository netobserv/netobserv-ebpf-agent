package ifaces

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	netnsVolume = "/var/run/netns"
)

var log = logrus.WithField("component", "ifaces.Watcher")

// Watcher uses system's netlink to get real-time information events about network interfaces'
// addition or removal.
type Watcher struct {
	bufLen     int
	current    map[InterfaceKey]Interface
	mapSize    int
	interfaces func(handle netns.NsHandle, ns string) ([]Interface, error)
	// linkSubscriber abstracts netlink.LinkSubscribe implementation, allowing the injection of
	// mocks for unit testing
	linkSubscriberAt func(ns netns.NsHandle, ch chan<- netlink.LinkUpdate, done <-chan struct{}) error
	mutex            *sync.Mutex
	netnsWatcher     *fsnotify.Watcher
	nsDone           sync.Map
}

func NewWatcher(bufLen int, m *metrics.Metrics) *Watcher {
	current := map[InterfaceKey]Interface{}
	w := &Watcher{
		bufLen:           bufLen,
		current:          current,
		interfaces:       netInterfaces,
		linkSubscriberAt: netlink.LinkSubscribeAt,
		mutex:            &sync.Mutex{},
		netnsWatcher:     &fsnotify.Watcher{},
		nsDone:           sync.Map{},
	}
	m.CreateInterfaceBufferGauge("watcher", func() float64 { return float64(w.mapSize) })
	return w
}

func (w *Watcher) Subscribe(ctx context.Context) (<-chan Event, error) {
	out := make(chan Event, w.bufLen)
	netns, err := getNetNS()
	if err != nil {
		w.nsDone.Store("", make(chan struct{}))
		go w.sendUpdates(ctx, "", out)
	} else {
		for _, n := range netns {
			w.nsDone.Store(n, make(chan struct{}))
			go w.sendUpdates(ctx, n, out)
		}
	}
	// register to get notification when netns is created or deleted and register for link update for new netns
	w.netnsNotify(ctx, out)
	return out, nil
}

func (w *Watcher) sendUpdates(ctx context.Context, ns string, out chan Event) {
	var netnsHandle netns.NsHandle
	var err error
	ch, ok := w.nsDone.Load(ns)
	if !ok {
		log.WithError(err).Warnf("netns %s not found in netns map", ns)
		return
	}
	doneChan := ch.(chan struct{})
	defer func() {
		if netnsHandle.IsOpen() {
			netnsHandle.Close()
		}
	}()
	// subscribe for interface events
	links := make(chan netlink.LinkUpdate)
	if err = wait.PollUntilContextTimeout(ctx, 50*time.Microsecond, time.Second, true, func(_ context.Context) (done bool, err error) {
		if ns == "" {
			netnsHandle = netns.None()
		} else {
			if netnsHandle, err = netns.GetFromName(ns); err != nil {
				log.WithError(err).Warnf("can't get netns %s", ns)
				return false, nil
			}
		}
		if err = w.linkSubscriberAt(netnsHandle, links, doneChan); err != nil {
			log.WithFields(logrus.Fields{
				"netns":       ns,
				"netnsHandle": netnsHandle.String(),
				"error":       err,
			}).Debug("linkSubscribe failed retry")
			if err := netnsHandle.Close(); err != nil {
				log.WithError(err).Warn("netnsHandle close failed")
			}
			return false, nil
		}

		log.WithFields(logrus.Fields{
			"netns":       ns,
			"netnsHandle": netnsHandle.String(),
		}).Debug("linkSubscribe to receive links update")
		return true, nil
	}); err != nil {
		log.WithError(err).Errorf("can't subscribe to links netns %s netnsHandle %s", ns, netnsHandle.String())
		return
	}

	// before sending netlink updates, send all the existing interfaces at the moment of starting
	// the Watcher
	if netnsHandle.IsOpen() || netnsHandle.Equal(netns.None()) {
		if ifaces, err := w.interfaces(netnsHandle, ns); err != nil {
			log.WithError(err).Error("can't fetch network interfaces. You might be missing flows")
		} else {
			for _, iface := range ifaces {
				w.mutex.Lock()
				w.current[iface.InterfaceKey] = iface
				w.mapSize = len(w.current)
				w.mutex.Unlock()
				out <- Event{Type: EventAdded, Interface: iface}
			}
		}
	}

	for link := range links {
		attrs := link.Attrs()
		if attrs == nil {
			log.WithField("link", link).Debug("received link update without attributes. Ignoring")
			continue
		}
		mac, err := macToFixed6(attrs.HardwareAddr)
		if err != nil {
			log.WithField("link", link).Debugf("ignoring link update with invalid MAC: %s", err.Error())
			continue
		}
		iface := NewInterface(attrs.Index, attrs.Name, mac, netnsHandle, ns)
		w.mutex.Lock()
		if link.Flags&(syscall.IFF_UP|syscall.IFF_RUNNING) != 0 && attrs.OperState == netlink.OperUp {
			log.WithFields(logrus.Fields{
				"operstate": attrs.OperState,
				"flags":     attrs.Flags,
				"name":      attrs.Name,
				"netns":     netnsHandle.String(),
			}).Debug("Interface up and running")
			if _, ok := w.current[iface.InterfaceKey]; !ok {
				log.Debugf(
					"found new link: %s=>[Index=%d, MAC=%s, MasterIdx=%d, ParentIdx=%d, Namespace=%s]",
					attrs.Name,
					attrs.Index,
					attrs.HardwareAddr.String(),
					attrs.MasterIndex,
					attrs.ParentIndex,
					ns,
				)
				w.current[iface.InterfaceKey] = iface
				out <- Event{Type: EventAdded, Interface: iface}
			}
		} else {
			log.WithFields(logrus.Fields{
				"operstate": attrs.OperState,
				"flags":     attrs.Flags,
				"name":      attrs.Name,
				"netns":     netnsHandle.String(),
			}).Debug("Interface down or not running")
			if storedIface, ok := w.current[iface.InterfaceKey]; ok {
				delete(w.current, iface.InterfaceKey)
				out <- Event{Type: EventDeleted, Interface: storedIface}
			}
		}
		w.mapSize = len(w.current)
		w.mutex.Unlock()
	}
}

func getNetNS() ([]string, error) {
	log := logrus.WithField("component", "ifaces.Watcher")
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

func (w *Watcher) handleEvent(ctx context.Context, event fsnotify.Event, out chan Event) {
	ns := filepath.Base(event.Name)

	switch {
	case event.Op&fsnotify.Create == fsnotify.Create:
		log.WithField("netns", ns).Debug("netns create notification")
		w.createNamespace(ctx, ns, out)
	case event.Op&fsnotify.Remove == fsnotify.Remove:
		log.WithField("netns", ns).Debug("netns delete notification")
		w.deleteNamespace(ns)
	}
}

func (w *Watcher) createNamespace(ctx context.Context, ns string, out chan Event) {
	if ch, ok := w.nsDone.Load(ns); ok {
		log.WithField("netns", ns).Debug("netns channel already exists, deleting it")
		close(ch.(chan struct{}))
		w.nsDone.Delete(ns)
	}

	w.nsDone.Store(ns, make(chan struct{}))
	go w.sendUpdates(ctx, ns, out)
}

func (w *Watcher) deleteNamespace(ns string) {
	if ch, ok := w.nsDone.Load(ns); ok {
		close(ch.(chan struct{}))
		w.nsDone.Delete(ns)
	} else {
		log.WithField("netns", ns).Debug("netns delete but no channel exists")
	}
}

func (w *Watcher) netnsNotify(ctx context.Context, out chan Event) {
	var err error

	w.netnsWatcher, err = fsnotify.NewWatcher()
	if err != nil {
		log.WithError(err).Error("can't subscribe fsnotify")
		return
	}
	// Start a goroutine to handle netns events
	go func() {
		for {
			select {
			case event, ok := <-w.netnsWatcher.Events:
				if !ok {
					return
				}
				w.handleEvent(ctx, event, out)
			case err, ok := <-w.netnsWatcher.Errors:
				if !ok {
					return
				}
				log.WithError(err).Error("netns watcher detected an error")
			}
		}
	}()

	err = w.netnsWatcher.Add(netnsVolume)
	if err != nil {
		log.Warningf("failed to add watcher to netns directory err: %v [Ignore if the agent privileged flag is not set]", err)
	}
}

func macToFixed6(in net.HardwareAddr) ([6]uint8, error) {
	if in == nil {
		return [6]uint8{}, fmt.Errorf("MAC is nil")
	}
	if len(in) < 6 {
		return [6]uint8{}, fmt.Errorf("MAC too small: %v", in)
	}
	return [6]uint8(in[0:6]), nil
}
