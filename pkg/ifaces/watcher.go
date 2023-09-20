package ifaces

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const (
	netnsVolume = "/var/run/netns"
)

// Watcher uses system's netlink to get real-time information events about network interfaces'
// addition or removal.
type Watcher struct {
	bufLen     int
	current    map[Interface]struct{}
	interfaces func() ([]Interface, error)
	// linkSubscriber abstracts netlink.LinkSubscribe implementation, allowing the injection of
	// mocks for unit testing
	linkSubscriberAt func(ns netns.NsHandle, ch chan<- netlink.LinkUpdate, done <-chan struct{}) error
	mutex            *sync.Mutex
	netnsWatcher     *fsnotify.Watcher
}

func NewWatcher(bufLen int) *Watcher {
	return &Watcher{
		bufLen:           bufLen,
		current:          map[Interface]struct{}{},
		interfaces:       netInterfaces,
		linkSubscriberAt: netlink.LinkSubscribeAt,
		mutex:            &sync.Mutex{},
		netnsWatcher:     &fsnotify.Watcher{},
	}
}

func (w *Watcher) Subscribe(ctx context.Context) (<-chan Event, error) {
	out := make(chan Event, w.bufLen)

	nsHandles, err := getNetNSHandles()
	if err != nil {
		go w.sendUpdates(ctx, netns.None(), out)
	} else {
		for _, nsh := range nsHandles {
			nsHandle := nsh
			go w.sendUpdates(ctx, nsHandle, out)
		}
	}
	// register to get notification when netns is created or deleted and register for link update for new netns
	w.netnsNotify(ctx, out)
	return out, nil
}

func (w *Watcher) sendUpdates(ctx context.Context, netnsHandle netns.NsHandle, out chan Event) {
	log := logrus.WithField("component", "ifaces.Watcher")
	// subscribe for interface events
	links := make(chan netlink.LinkUpdate)
	log.WithField("netns", netnsHandle.String()).Debug("linkSubscribe to receive links update")
	if err := w.linkSubscriberAt(netnsHandle, links, ctx.Done()); err != nil {
		log.WithError(err).Errorf("can't subscribe to links netns %s", netnsHandle.String())
		return
	}

	// before sending netlink updates, send all the existing interfaces at the moment of starting
	// the Watcher
	if netnsHandle.Equal(netns.None()) {
		if names, err := w.interfaces(); err != nil {
			log.WithError(err).Error("can't fetch network interfaces. You might be missing flows")
		} else {
			for _, name := range names {
				iface := Interface{Name: name.Name, Index: name.Index, NetNS: netnsHandle}
				w.mutex.Lock()
				w.current[iface] = struct{}{}
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
		iface := Interface{Name: attrs.Name, Index: attrs.Index, NetNS: netnsHandle}
		w.mutex.Lock()
		if link.Flags&(syscall.IFF_UP|syscall.IFF_RUNNING) != 0 && attrs.OperState == netlink.OperUp {
			log.WithFields(logrus.Fields{
				"operstate": attrs.OperState,
				"flags":     attrs.Flags,
				"name":      attrs.Name,
				"netns":     netnsHandle.String(),
			}).Debug("Interface up and running")
			if _, ok := w.current[iface]; !ok {
				w.current[iface] = struct{}{}
				out <- Event{Type: EventAdded, Interface: iface}
			}
		} else {
			log.WithFields(logrus.Fields{
				"operstate": attrs.OperState,
				"flags":     attrs.Flags,
				"name":      attrs.Name,
				"netns":     netnsHandle.String(),
			}).Debug("Interface down or not running")
			if _, ok := w.current[iface]; ok {
				delete(w.current, iface)
				out <- Event{Type: EventDeleted, Interface: iface}
			}
		}
		w.mutex.Unlock()
	}
}

func getNetNSHandles() ([]netns.NsHandle, error) {
	log := logrus.WithField("component", "ifaces.Watcher")
	files, err := os.ReadDir(netnsVolume)
	if err != nil {
		log.Warningf("can't detect any network-namespaces err: %v [Ignore if the agent privileged flag is not set]", err)
		return nil, fmt.Errorf("failed to list network-namespaces: %w", err)
	}

	handles := []netns.NsHandle{netns.None()}
	if len(files) == 0 {
		log.WithField("netns", files).Debug("empty network-namespaces list")
		return handles, nil
	}
	for _, f := range files {
		ns := f.Name()
		handle, err := netns.GetFromName(ns)
		if err != nil {
			log.WithField("netns", ns).Debug("can't get NsHandle for this netns. Ignoring")
			continue
		}
		handles = append(handles, handle)
		log.WithFields(logrus.Fields{
			"netns":  ns,
			"handle": handle.String(),
		}).Debug("Detected network-namespace")

	}

	return handles, nil
}

func (w *Watcher) netnsNotify(ctx context.Context, out chan Event) {
	var err error
	log := logrus.WithField("component", "ifaces.Watcher")

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
				if event.Op&fsnotify.Create == fsnotify.Create {
					ns := filepath.Base(event.Name)
					log.WithField("netns", ns).Debug("netns notification")
					handle, err := netns.GetFromName(ns)
					if err != nil {
						log.WithField("netns", ns).Debug("can't get NsHandle for this netns. Ignoring")
						return
					}
					go w.sendUpdates(ctx, handle, out)
				}
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
