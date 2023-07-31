// Package grpc provides the basic interfaces to build a gRPC+Protobuf flows client & server
package grpc

import (
	"crypto/tls"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/utils"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var glog = logrus.WithField("component", "grpc/Client")

// ClientConnection wraps a gRPC+protobuf connection
type ClientConnection struct {
	client pbflow.CollectorClient
	conn   *grpc.ClientConn
}

func ConnectClient(hostIP string, hostPort int, tlsConfig *tls.Config) (*ClientConnection, error) {
	var creds credentials.TransportCredentials
	if tlsConfig != nil {
		creds = credentials.NewTLS(tlsConfig)
	} else {
		glog.Warn("TLS not configured: using insecure GRPC connection")
		creds = insecure.NewCredentials()
	}
	// TODO: allow configuring some options (keepalive, backoff...)
	socket := utils.GetSocket(hostIP, hostPort)
	conn, err := grpc.Dial(socket, grpc.WithTransportCredentials(creds))
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
