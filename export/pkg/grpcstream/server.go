package grpcstream

import (
	"fmt"
	"io"
	"net"

	"github.com/netobserv/netobserv-agent/export/pkg/pbflow"
	"google.golang.org/grpc"
)

func StartServer(port int, recordForwarder chan<- *pbflow.Record) (func(), error) {
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, err
	}
	var opts []grpc.ServerOption
	// TODO: set server options
	grpcServer := grpc.NewServer(opts...)
	pbflow.RegisterStreamedCollectorServer(grpcServer, &collectorAPI{
		recordForwarder: recordForwarder,
	})
	return grpcServer.GracefulStop, grpcServer.Serve(lis)
}

type collectorAPI struct {
	pbflow.UnimplementedStreamedCollectorServer
	recordForwarder chan<- *pbflow.Record
}

var okReply = &pbflow.CollectorReply{}

func (c *collectorAPI) Send(stream pbflow.StreamedCollector_SendServer) error {
	for {
		record, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return stream.SendAndClose(okReply)
			}
			return err
		}
		c.recordForwarder <- record
	}
}
