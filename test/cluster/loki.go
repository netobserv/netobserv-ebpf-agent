package cluster

import (
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"
)

const (
	pathReady = "/ready"
)

var llog = logrus.WithField("component", "Loki")

type Loki struct {
	BaseURL string
}

func (l *Loki) Ready() error {
	client := http.Client{}
	gurl := l.BaseURL + pathReady
	if resp, err := client.Get(gurl); err != nil {
		return fmt.Errorf("loki is not ready: %w", err)
	} else if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("loki is not ready. Status code %d", resp.StatusCode)
	}
	return nil
}
