package main

import (
	"context"
	"fmt"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/agent"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/exporter"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/grpc"
	"github.com/sirupsen/logrus"
)

var glog = logrus.WithField("component", "exporter/GRPCProto")

func ExporterPlugin(cfg *agent.Config) (agent.Exporter, error) {
	if cfg.TargetHost == "" || cfg.TargetPort == 0 {
		return nil, fmt.Errorf("missing target host or port: %s:%d",
			cfg.TargetHost, cfg.TargetPort)
	}
	target := fmt.Sprintf("%s:%d", cfg.TargetHost, cfg.TargetPort)
	return StartGRPCProto(target)
}

// GRPCProto flow exporter. Its ExportFlows method accepts slices of *flow.Record
// by its input channel, converts them to *pbflow.Records instances, and submits
// them to the collector.
type GRPCProto struct {
	hostPort   string
	clientConn *grpc.ClientConnection
}

func StartGRPCProto(hostPort string) (*GRPCProto, error) {
	clientConn, err := grpc.ConnectClient(hostPort)
	if err != nil {
		return nil, err
	}
	return &GRPCProto{
		hostPort:   hostPort,
		clientConn: clientConn,
	}, nil
}

// ExportFlows accepts slices of *flow.Record by its input channel, converts them
// to *pbflow.Records instances, and submits them to the collector.
func (g *GRPCProto) ExportFlows(input <-chan []*flow.Record) {
	log := glog.WithField("collector", g.hostPort)
	for inputRecords := range input {
		pbRecords := exporter.FlowsToPB(inputRecords)
		log.Debugf("sending %d records", len(pbRecords.Entries))
		if _, err := g.clientConn.Client().Send(context.TODO(), pbRecords); err != nil {
			log.WithError(err).Error("couldn't send flow records to collector")
		}
	}
	if err := g.clientConn.Close(); err != nil {
		log.WithError(err).Warn("couldn't close flow export client")
	}
}
