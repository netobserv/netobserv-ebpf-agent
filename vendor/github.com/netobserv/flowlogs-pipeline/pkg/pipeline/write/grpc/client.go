package grpc

import (
	"crypto/tls"

	pb "github.com/netobserv/flowlogs-pipeline/pkg/pipeline/write/grpc/genericmap"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/utils"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var glog = logrus.WithField("component", "write.GRPCClient")

// ClientConnection wraps a gRPC+protobuf connection
type ClientConnection struct {
	client pb.CollectorClient
	conn   *grpc.ClientConn
}

func ConnectClient(hostIP string, hostPort int, tlsConfig *tls.Config) (*ClientConnection, error) {
	// Set up a connection to the server.
	var creds credentials.TransportCredentials
	if tlsConfig != nil {
		creds = credentials.NewTLS(tlsConfig)
	} else {
		glog.Info("Using GRPC - No TLS")
		creds = insecure.NewCredentials()
	}
	socket := utils.GetSocket(hostIP, hostPort)
	conn, err := grpc.NewClient(socket, grpc.WithTransportCredentials(creds))

	if err != nil {
		return nil, err
	}

	return &ClientConnection{
		client: pb.NewCollectorClient(conn),
		conn:   conn,
	}, nil
}

func (cp *ClientConnection) Client() pb.CollectorClient {
	return cp.client
}

func (cp *ClientConnection) Close() error {
	return cp.conn.Close()
}
