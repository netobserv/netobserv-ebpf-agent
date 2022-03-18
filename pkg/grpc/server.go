package grpc

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/netobserv/netobserv-agent/pkg/pbflow"
)

// CollectorServer wraps a Flow Collector connection & session
type CollectorServer struct {
	grpcServer *grpc.Server
}

// StartCollector listens for gRPC+Protobuf flows in the given port, and forwards each set of
// *pbflow.Records by the provided channel.
func StartCollector(port int, recordForwarder chan<- *pbflow.Records) (*CollectorServer, error) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	// TODO: set server option arguments
	grpcServer := grpc.NewServer()
	pbflow.RegisterCollectorServer(grpcServer, &collectorAPI{
		recordForwarder: recordForwarder,
	})
	reflection.Register(grpcServer)
	// TODO: shall it run in background? otherwise it does not have sense to return the collector server
	if err := grpcServer.Serve(lis); err != nil {
		return nil, err
	}
	return &CollectorServer{
		grpcServer: grpcServer,
	}, nil
}

func (c *CollectorServer) Close() error {
	c.grpcServer.Stop()
	return nil
}

type collectorAPI struct {
	pbflow.UnimplementedCollectorServer
	recordForwarder chan<- *pbflow.Records
}

var okReply = &pbflow.CollectorReply{}

func (c *collectorAPI) Send(_ context.Context, records *pbflow.Records) (*pbflow.CollectorReply, error) {
	c.recordForwarder <- records
	return okReply, nil
}
