package prometheus

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/server"

	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

var (
	plog       = logrus.WithField("component", "prometheus")
	maybePanic = plog.Fatalf
)

// InitializePrometheus starts the global Prometheus server, used for operational metrics and prom-encode stages if they don't override the server settings
func InitializePrometheus(settings *metrics.Settings) *http.Server {
	return StartServerAsync(settings, nil)
}

// StartServerAsync listens for prometheus resource usage requests
func StartServerAsync(conn *metrics.Settings, registry *prom.Registry) *http.Server {
	// create prometheus server for operational metrics
	// if value of address is empty, then by default it will take 0.0.0.0
	port := conn.Port
	if port == 0 {
		port = 9090
	}
	addr := fmt.Sprintf("%s:%v", conn.Address, port)
	plog.Infof("StartServerAsync: addr = %s", addr)

	httpServer := &http.Server{
		Addr: addr,
		// TLS clients must use TLS 1.2 or higher
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	// The Handler function provides a default handler to expose metrics
	// via an HTTP server. "/metrics" is the usual endpoint for that.
	mux := http.NewServeMux()
	if registry == nil {
		mux.Handle("/metrics", promhttp.Handler())
	} else {
		mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	}
	httpServer.Handler = mux
	httpServer = server.Default(httpServer)

	go func() {
		var err error
		if conn.TLS != nil {
			err = httpServer.ListenAndServeTLS(conn.TLS.CertPath, conn.TLS.KeyPath)
		} else {
			err = httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			maybePanic("error in http.ListenAndServe: %v", err)
		}
	}()

	return httpServer
}
