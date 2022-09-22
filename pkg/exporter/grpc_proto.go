package exporter

import (
	"context"
	"io"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/grpc"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"github.com/sirupsen/logrus"
)

var glog = logrus.WithField("component", "exporter/GRPCProto")

// GRPCProto flow exporter. Its ExportFlows method accepts slices of *flow.Record
// by its input channel, converts them to *pbflow.Records instances, and submits
// them to the collector.
type GRPCProto struct {
	hostPort          string
	clientConn        clientConnector
	maxMessageEntries int
}

type clientConnector interface {
	io.Closer
	Client() pbflow.CollectorClient
}

func StartGRPCProto(hostPort string, maxMessageEntries int) (*GRPCProto, error) {
	clientConn, err := grpc.ConnectClient(hostPort)
	if err != nil {
		return nil, err
	}
	return &GRPCProto{
		hostPort:          hostPort,
		clientConn:        clientConn,
		maxMessageEntries: maxMessageEntries,
	}, nil
}

// ExportFlows accepts slices of *flow.Record by its input channel, converts them
// to *pbflow.Records instances, and submits them to the collector.
func (g *GRPCProto) ExportFlows(input <-chan []*flow.Record) {
	log := glog.WithField("collector", g.hostPort)
	for inputRecords := range input {
		g.batchAndSubmit(inputRecords, log)
	}
	if err := g.clientConn.Close(); err != nil {
		log.WithError(err).Warn("couldn't close flow export client")
	}
}

// batchAndSubmit forwards the messages to the GRPC collector. If the maxMessageEntries value
// is set, it splits the payload in multiple payloads of that size and submits them as different
// messages
func (g *GRPCProto) batchAndSubmit(records []*flow.Record, log logrus.FieldLogger) {
	for g.maxMessageEntries != 0 && g.maxMessageEntries < len(records) {
		pbRecords := flowsToPB(records[:g.maxMessageEntries])
		records = records[g.maxMessageEntries:]
		log.Debugf("sending %d records (%d left)", len(pbRecords.Entries), len(records))
		if _, err := g.clientConn.Client().Send(context.TODO(), pbRecords); err != nil {
			log.WithError(err).Error("couldn't send flow records to collector")
		}
	}
	pbRecords := flowsToPB(records)
	log.Debugf("sending %d records", len(pbRecords.Entries))
	if _, err := g.clientConn.Client().Send(context.TODO(), pbRecords); err != nil {
		log.WithError(err).Error("couldn't send flow records to collector")
	}
}
