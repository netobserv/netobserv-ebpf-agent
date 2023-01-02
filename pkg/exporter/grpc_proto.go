package exporter

import (
	"context"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/grpc"
	"github.com/sirupsen/logrus"
)

var glog = logrus.WithField("component", "exporter/GRPCProto")

// GRPCProto flow exporter. Its ExportFlows method accepts slices of *flow.Record
// by its input channel, converts them to *pbflow.Records instances, and submits
// them to the collector.
type GRPCProto struct {
	hostPort   string
	clientConn *grpc.ClientConnection
	// maxFlowsPerMessage limits the maximum number of flows per GRPC message.
	// If a message contains more flows than this number, the GRPC message will be split into
	// multiple messages.
	maxFlowsPerMessage int
}

func StartGRPCProto(hostPort string, maxFlowsPerMessage int) (*GRPCProto, error) {
	clientConn, err := grpc.ConnectClient(hostPort)
	if err != nil {
		return nil, err
	}
	return &GRPCProto{
		hostPort:           hostPort,
		clientConn:         clientConn,
		maxFlowsPerMessage: maxFlowsPerMessage,
	}, nil
}

// ExportFlows accepts slices of *flow.Record by its input channel, converts them
// to *pbflow.Records instances, and submits them to the collector.
func (g *GRPCProto) ExportFlows(input <-chan []*flow.Record) {
	log := glog.WithField("collector", g.hostPort)
	for inputRecords := range input {
		for _, pbRecords := range flowsToPB(inputRecords, g.maxFlowsPerMessage) {
			log.Debugf("sending %d records", len(pbRecords.Entries))
			if _, err := g.clientConn.Client().Send(context.TODO(), pbRecords); err != nil {
				log.WithError(err).Error("couldn't send flow records to collector")
			}
		}
	}
	if err := g.clientConn.Close(); err != nil {
		log.WithError(err).Warn("couldn't close flow export client")
	}
}
