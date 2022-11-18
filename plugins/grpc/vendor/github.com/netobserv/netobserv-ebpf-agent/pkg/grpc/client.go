// Package grpc provides the basic interfaces to build a gRPC+Protobuf flows client & server
package grpc

import (
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ClientConnection wraps a gRPC+protobuf connection
type ClientConnection struct {
	client pbflow.CollectorClient
	conn   *grpc.ClientConn
}

func ConnectClient(address string) (*ClientConnection, error) {
	// TODO: allow configuring some options (keepalive, backoff...)
	conn, err := grpc.Dial(address,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
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
