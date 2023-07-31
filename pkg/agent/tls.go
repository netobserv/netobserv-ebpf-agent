package agent

import (
	"crypto/tls"
	"crypto/x509"
	"os"
)

func buildTargetTLSConfig(cfg *Config) (*tls.Config, error) {
	return buildTLSConfig(
		cfg.TargetTLSCACertPath,
		cfg.TargetTLSUserCertPath,
		cfg.TargetTLSUserKeyPath,
		cfg.TargetTLSInsecureSkipVerify,
	)
}

func buildKafkaTLSConfig(cfg *Config) (*tls.Config, error) {
	return buildTLSConfig(
		cfg.KafkaTLSCACertPath,
		cfg.KafkaTLSUserCertPath,
		cfg.KafkaTLSUserKeyPath,
		cfg.KafkaTLSInsecureSkipVerify,
	)
}

func buildTLSConfig(caPath, userCertPath, userKeyPath string, insecure bool) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecure,
	}
	if caPath != "" {
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		tlsConfig.RootCAs.AppendCertsFromPEM(caCert)

		if userCertPath != "" && userKeyPath != "" {
			userCert, err := os.ReadFile(userCertPath)
			if err != nil {
				return nil, err
			}
			userKey, err := os.ReadFile(userKeyPath)
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
