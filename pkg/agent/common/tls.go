package common

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
)

func BuildTLSConfig(cfg *config.Agent) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.Flows.KafkaTLSInsecureSkipVerify,
		MinVersion:         tls.VersionTLS13,
	}
	if cfg.Flows.KafkaTLSCACertPath != "" {
		caCert, err := os.ReadFile(cfg.Flows.KafkaTLSCACertPath)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		tlsConfig.RootCAs.AppendCertsFromPEM(caCert)

		if cfg.Flows.KafkaTLSUserCertPath != "" && cfg.Flows.KafkaTLSUserKeyPath != "" {
			userCert, err := os.ReadFile(cfg.Flows.KafkaTLSUserCertPath)
			if err != nil {
				return nil, err
			}
			userKey, err := os.ReadFile(cfg.Flows.KafkaTLSUserKeyPath)
			if err != nil {
				return nil, err
			}
			pair, err := tls.X509KeyPair([]byte(userCert), []byte(userKey))
			if err != nil {
				return nil, err
			}
			tlsConfig.Certificates = []tls.Certificate{pair}
		}
	}
	return tlsConfig, nil
}
