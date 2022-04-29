package ifaces

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
)

type Poller struct {
	period     time.Duration
	current    map[Name]struct{}
	interfaces func() ([]Name, error)
	bufLen     int
}

func NewPoller(period time.Duration, bufLen int) *Poller {
	return &Poller{
		period:     period,
		bufLen:     bufLen,
		interfaces: interfaces,
		current:    map[Name]struct{}{},
	}
}

func (np *Poller) Subscribe(ctx context.Context) (<-chan Event, error) {
	log := logrus.WithField("component", "ifaces.Poller")
	log.WithField("period", np.period).Debug("subscribing to Interface events")
	out := make(chan Event, np.bufLen)
	go func() {
		ticker := time.NewTicker(np.period)
		defer ticker.Stop()
		for {
			if names, err := np.interfaces(); err != nil {
				log.WithError(err).Warn("fetching interface names")
			} else {
				log.WithField("names", names).Debug("fetched interface names")
				np.diffNames(out, names)
			}
			select {
			case <-ctx.Done():
				log.Debug("stopped")
				close(out)
				return
			case <-ticker.C:
				// continue after period
			}
		}
	}()
	return out, nil
}

func (np *Poller) diffNames(events chan Event, names []Name) {
	// Check for new interfaces
	acquired := map[Name]struct{}{}
	for _, n := range names {
		acquired[n] = struct{}{}
		if _, ok := np.current[n]; !ok {
			ilog.WithField("interface", n).Debug("added network interface")
			np.current[n] = struct{}{}
			events <- Event{
				Type:      EventAdded,
				Interface: n,
			}
		}
	}
	// Check for deleted interfaces
	for n := range np.current {
		if _, ok := acquired[n]; !ok {
			delete(np.current, n)
			ilog.WithField("interface", n).Debug("deleted network interface")
			events <- Event{
				Type:      EventDeleted,
				Interface: n,
			}
		}
	}
}
