package agent

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
)

func buildTLSConfig(cfg *Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.KafkaTLSInsecureSkipVerify,
	}
	if cfg.KafkaTLSCACertPath != "" {
		caCert, err := ioutil.ReadFile(cfg.KafkaTLSCACertPath)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		tlsConfig.RootCAs.AppendCertsFromPEM(caCert)

		if cfg.KafkaTLSUserCertPath != "" && cfg.KafkaTLSUserKeyPath != "" {
			userCert, err := ioutil.ReadFile(cfg.KafkaTLSUserCertPath)
			if err != nil {
				return nil, err
			}
			userKey, err := ioutil.ReadFile(cfg.KafkaTLSUserKeyPath)
			if err != nil {
				return nil, err
			}
			pair, err := tls.X509KeyPair([]byte(userCert), []byte(userKey))
			if err != nil {
				return nil, err
			}
			tlsConfig.Certificates = []tls.Certificate{pair}
		}
		return tlsConfig, nil
	}
	return nil, nil
}
