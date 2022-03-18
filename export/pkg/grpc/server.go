package grpc

import (
	"context"
	"fmt"
	"net"

	"github.com/netobserv/netobserv-agent/export/pkg/pbflow"
	"google.golang.org/grpc"
)

func StartServer(port int, recordForwarder chan<- *pbflow.Records) (func(), error) {
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, err
	}
	var opts []grpc.ServerOption
	// TODO: set server options
	grpcServer := grpc.NewServer(opts...)
	pbflow.RegisterCollectorServer(grpcServer, &collectorAPI{
		recordForwarder: recordForwarder,
	})
	return grpcServer.GracefulStop, grpcServer.Serve(lis)
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
