package ifaces

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
)

var ifaceSeparator = []byte{':'}

type Watcher struct {
	netDevPath string
	bufLen     int
}

func NewWatcher(netDevPath string, bufLen int) *Watcher {
	return &Watcher{
		netDevPath: netDevPath,
		bufLen:     bufLen,
	}
}

func (w *Watcher) Subscribe(ctx context.Context) (<-chan []Name, error) {
	log := logrus.WithFields(logrus.Fields{
		"component": "ifaces.Watcher",
		"path":      w.netDevPath,
	})
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("can't start file watcher: %w", err)
	}
	if err := watcher.Add(w.netDevPath); err != nil {
		return nil, fmt.Errorf("can't subscribe for changes in %s: %w", w.netDevPath, err)
	}
	out := make(chan []Name, w.bufLen)
	go func() {
		w.fetchAndForwardNames(log, out)
		for {
			select {
			case <-ctx.Done():
				log.Debug("stopped")
				close(out)
				return
			case event := <-watcher.Events:
				log.WithField("event", event).Debug("received an event")
				if event.Op&(fsnotify.Create|fsnotify.Write) != 0 {
					w.fetchAndForwardNames(log, out)
				}
			case err := <-watcher.Errors:
				log.WithError(err).Warn("file watcher forwarded an error")
			}
		}
	}()

	return out, nil
}

func (w *Watcher) fetchAndForwardNames(log *logrus.Entry, out chan []Name) {
	if netDev, err := os.Open(w.netDevPath); err != nil {
		log.WithError(err).Error("can't read devices file")
	} else {
		names, err := parseNetDev(netDev)
		if err != nil {
			log.WithError(err).Error("scanning devices file")
		}
		if err := netDev.Close(); err != nil {
			log.WithError(err).Error("can't close file")
		}
		out <- names
	}
}

// parseNetDev extracts the interface names according to the format specified in
// https://www.kernel.org/doc/Documentation/filesystems/proc.txt
func parseNetDev(in io.Reader) ([]Name, error) {
	contents := bufio.NewScanner(in)
	var names []Name
	for contents.Scan() {
		iface := bytes.Split(contents.Bytes(), ifaceSeparator)
		if len(iface) != 2 {
			// wrong format or just a header line. Ignoring
			continue
		}
		names = append(names, Name(bytes.Trim(iface[0], " \t")))
	}
	return names, contents.Err()
}
