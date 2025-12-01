// Package flowgrpc provides the basic interfaces to build a gRPC+Protobuf flows client & server
package flowgrpc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/utils"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var clog = logrus.WithField("component", "grpc.Client")

// ClientConnection wraps a gRPC+protobuf connection
type ClientConnection struct {
	client pbflow.CollectorClient
	conn   *grpc.ClientConn
}

func ConnectClient(hostIP string, hostPort int, caPath, userCertPath, userKeyPath string) (*ClientConnection, error) {
	// TODO: allow configuring more options (keepalive, backoff...)
	var opts []grpc.DialOption
	if caPath == "" {
		clog.Info("Starting GRPC client - no TLS")
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// Configure TLS (server CA)
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("Cannot load CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caCert)
		tlsConfig := &tls.Config{
			RootCAs: pool,
		}
		if userCertPath != "" && userKeyPath != "" {
			clog.Info("Starting GRPC client with mTLS")
			// Configure mTLS (client certificates)
			cert, err := tls.LoadX509KeyPair(userCertPath, userKeyPath)
			if err != nil {
				return nil, fmt.Errorf("Cannot load client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		} else {
			clog.Info("Starting GRPC client with TLS")
		}

		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	}
	socket := utils.GetSocket(hostIP, hostPort)
	conn, err := grpc.NewClient(socket, opts...)
	if err != nil {
		return nil, err
	}
	return &ClientConnection{
		client: pbflow.NewCollectorClient(conn),
		conn:   conn,
	}, nil
}

func (cp *ClientConnection) Client() pbflow.CollectorClient {
	return cp.client
}

func (cp *ClientConnection) Close() error {
	return cp.conn.Close()
}
