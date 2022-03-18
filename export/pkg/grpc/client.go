package grpc

import (
	"github.com/netobserv/netobserv-agent/export/pkg/pbflow"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func StartClient(address string) (pbflow.CollectorClient, func() error, error) {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	// TODO: set options
	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		return nil, nil, err
	}
	return pbflow.NewCollectorClient(conn), conn.Close, nil
}
