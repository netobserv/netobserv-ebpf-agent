package ifaces

import (
	"context"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type Watcher struct {
	bufLen         int
	current        map[Name]struct{}
	interfaces     func() ([]Name, error)
	linkSubscriber func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error
}

func NewWatcher(bufLen int) *Watcher {
	return &Watcher{
		bufLen:         bufLen,
		current:        map[Name]struct{}{},
		interfaces:     interfaces,
		linkSubscriber: netlink.LinkSubscribe,
	}
}

func (w *Watcher) Subscribe(ctx context.Context) (<-chan Event, error) {
	out := make(chan Event, w.bufLen)

	go w.sendUpdates(ctx, out)

	return out, nil
}

func (w *Watcher) sendUpdates(ctx context.Context, out chan Event) {
	log := logrus.WithFields(logrus.Fields{
		"component": "ifaces.Watcher",
	})
	links := make(chan netlink.LinkUpdate)
	if err := w.linkSubscriber(links, ctx.Done()); err != nil {
		log.WithError(err).Error("can't subscribe to links")
		return
	}

	// before sending updates, send all the existing interfaces at the moment of starting the
	// agent
	if names, err := w.interfaces(); err != nil {
		log.WithError(err).Error("can't fetch network interfaces. You might be missing flows")
	} else {
		for _, name := range names {
			w.current[name] = struct{}{}
			out <- Event{Type: EventAdded, Interface: name}
		}
	}

	for link := range links {
		attrs := link.Attrs()
		if attrs == nil {
			log.WithField("link", link).Debug("received link update without attributes. Ignoring")
			continue
		}
		if link.Flags&(syscall.IFF_UP|syscall.IFF_RUNNING) != 0 {
			log.WithFields(logrus.Fields{
				"operstate": attrs.OperState,
				"flags":     attrs.Flags,
				"name":      attrs.Name,
			}).Debug("Interface up and running")
			if _, ok := w.current[Name(attrs.Name)]; !ok {
				w.current[Name(attrs.Name)] = struct{}{}
				out <- Event{Type: EventAdded, Interface: Name(attrs.Name)}
			}
		} else {
			log.WithFields(logrus.Fields{
				"operstate": attrs.OperState,
				"flags":     attrs.Flags,
				"name":      attrs.Name,
			}).Debug("Interface down or not running")
			if _, ok := w.current[Name(attrs.Name)]; ok {
				delete(w.current, Name(attrs.Name))
				out <- Event{Type: EventDeleted, Interface: Name(attrs.Name)}
			}
		}
	}
}
