package ingest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/flowlogs-pipeline/pkg/operational"
	pUtils "github.com/netobserv/flowlogs-pipeline/pkg/pipeline/utils"
	"github.com/netobserv/flowlogs-pipeline/pkg/utils"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/decode"
	grpc "github.com/netobserv/netobserv-ebpf-agent/pkg/grpc/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"

	"github.com/sirupsen/logrus"
	grpc2 "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

var glog = logrus.WithField("component", "ingest.GRPCProtobuf")

const (
	defaultBufferLen = 100
)

// GRPCProtobuf ingests data from the NetObserv eBPF Agent, using Protocol Buffers over gRPC
type GRPCProtobuf struct {
	collector   *grpc.CollectorServer
	flowPackets chan *pbflow.Records
	metrics     *metrics
}

func NewGRPCProtobuf(opMetrics *operational.Metrics, params config.StageParam) (*GRPCProtobuf, error) {
	cfg := api.IngestGRPCProto{}
	if params.Ingest != nil && params.Ingest.GRPC != nil {
		cfg = *params.Ingest.GRPC
	}
	if cfg.Port == 0 {
		return nil, errors.New("ingest port not specified")
	}
	bufLen := cfg.BufferLen
	if bufLen == 0 {
		bufLen = defaultBufferLen
	}
	flowPackets := make(chan *pbflow.Records, bufLen)
	metrics := newMetrics(
		opMetrics,
		params.Name,
		params.Ingest.Type,
		func() int { return len(flowPackets) },
		withLatency(),
		withBatchSizeBytes(),
		withStageDuration(),
	)
	var opts []grpc2.ServerOption
	// GRPC metrics
	opts = append(opts, grpc2.UnaryInterceptor(instrumentGRPC(metrics)))

	if cfg.CertPath != "" && cfg.KeyPath != "" {
		// TLS
		cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("cannot load configured certificate: %w", err)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.NoClientCert,
		}
		if cfg.ClientCAPath != "" {
			// mTLS
			caCert, err := os.ReadFile(cfg.ClientCAPath)
			if err != nil {
				return nil, fmt.Errorf("cannot load configured client CA certificate: %w", err)
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(caCert)
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
			tlsCfg.ClientCAs = pool
			glog.Info("Starting GRPC server with mTLS")
		} else {
			glog.Info("Starting GRPC server with TLS")
		}
		opts = append(opts, grpc2.Creds(credentials.NewTLS(tlsCfg)))
	} else {
		glog.Info("Starting GRPC server - no TLS")
	}

	collector, err := grpc.StartCollector(cfg.Port, flowPackets, grpc.WithGRPCServerOptions(opts...))
	if err != nil {
		return nil, err
	}
	return &GRPCProtobuf{
		collector:   collector,
		flowPackets: flowPackets,
		metrics:     metrics,
	}, nil
}

func (no *GRPCProtobuf) Ingest(out chan<- config.GenericMap) {
	no.metrics.createOutQueueLen(out)
	go func() {
		<-pUtils.ExitChannel()
		close(no.flowPackets)
		no.collector.Close()
	}()
	for fp := range no.flowPackets {
		glog.Debugf("Ingested %v records", len(fp.Entries))
		for _, entry := range fp.Entries {
			out <- decode.PBFlowToMap(entry)
		}
	}
}

func (no *GRPCProtobuf) Close() error {
	err := no.collector.Close()
	close(no.flowPackets)
	return err
}

func instrumentGRPC(m *metrics) grpc2.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc2.UnaryServerInfo,
		handler grpc2.UnaryHandler,
	) (resp interface{}, err error) {
		timer := m.stageDurationTimer()
		timeReceived := timer.Start()
		if info.FullMethod != "/pbflow.Collector/Send" {
			return handler(ctx, req)
		}
		flowRecords := req.(*pbflow.Records)

		// instrument difference between flow time and ingest time
		for _, entry := range flowRecords.Entries {
			delay := timeReceived.Sub(entry.TimeFlowEnd.AsTime()).Seconds()
			m.latency.Observe(delay)
		}

		// instrument flows processed counter
		m.flowsProcessed.Add(float64(len(flowRecords.Entries)))

		// instrument message bytes
		m.batchSizeBytes.Observe(float64(proto.Size(flowRecords)))

		resp, err = handler(ctx, req)
		if err != nil {
			// "trace" level used to minimize performance impact
			glog.Tracef("Reporting metric error: %v", err)
			m.error(utils.ConvertToString(status.Code(err)))
		}

		// Stage duration
		timer.ObserveMilliseconds()

		return resp, err
	}
}
