package ifaces

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

type Poller struct {
	period     time.Duration
	interfaces func() ([]Name, error)
}

func NewPoller(period time.Duration) *Poller {
	return &Poller{
		period:     period,
		interfaces: interfaces,
	}
}

func (np *Poller) Subscribe(ctx context.Context) (<-chan []Name, error) {
	log := logrus.WithField("component", "ifaces.Poller")
	log.WithField("period", np.period).Debug("subscribing to Interface events")
	out := make(chan []Name, 1)
	go func() {

		ticker := time.NewTicker(np.period)
		defer ticker.Stop()
		for {
			if names, err := np.interfaces(); err != nil {
				log.WithError(err).Warn("fetching interface names")
			} else {
				log.WithField("names", names).Debug("fetched interface names")
				out <- names
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

func interfaces() ([]Name, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("can't fetch interfaces: %w", err)
	}
	names := make([]Name, len(ifs))
	for i, ifc := range ifs {
		names[i] = Name(ifc.Name)
	}
	return names, nil
}
