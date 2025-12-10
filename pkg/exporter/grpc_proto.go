package exporter

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	grpc "github.com/netobserv/netobserv-ebpf-agent/pkg/grpc/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/utils"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

var glog = logrus.WithField("component", "exporter/GRPCProto")

const componentGRPC = "grpc"

// GRPCProto flow exporter. Its ExportFlows method accepts slices of *model.Record
// by its input channel, converts them to *pbflow.Records instances, and submits
// them to the collector.
type GRPCProto struct {
	hostIP       string
	hostPort     int
	caCertPath   string
	userCertPath string
	userKeyPath  string
	m            sync.RWMutex
	clientConn   *grpc.ClientConnection
	// maxFlowsPerMessage limits the maximum number of flows per GRPC message.
	// If a message contains more flows than this number, the GRPC message will be split into
	// multiple messages.
	maxFlowsPerMessage int
	reconnectTimer     time.Duration
	metrics            *metrics.Metrics
	batchCounterMetric prometheus.Counter
}

func StartGRPCProto(cfg *config.Agent, m *metrics.Metrics) (*GRPCProto, error) {
	exporter := GRPCProto{
		hostIP:             cfg.TargetHost,
		hostPort:           cfg.TargetPort,
		caCertPath:         cfg.TargetTLSCACertPath,
		userCertPath:       cfg.TargetTLSUserCertPath,
		userKeyPath:        cfg.TargetTLSUserKeyPath,
		maxFlowsPerMessage: cfg.GRPCMessageMaxFlows,
		reconnectTimer:     randomizeTimer(cfg),
		metrics:            m,
		batchCounterMetric: m.CreateBatchCounter(componentGRPC),
	}
	if err := exporter.reconnect(); err != nil {
		return nil, err
	}
	return &exporter, nil
}

func (g *GRPCProto) reconnect() error {
	g.m.Lock()
	defer g.m.Unlock()
	if g.clientConn != nil {
		if err := g.clientConn.Close(); err != nil {
			return err
		}
	}
	clientConn, err := grpc.ConnectClient(g.hostIP, g.hostPort, g.caCertPath, g.userCertPath, g.userKeyPath)
	if err != nil {
		return err
	}
	g.clientConn = clientConn
	return nil
}

// ExportFlows accepts slices of *model.Record by its input channel, converts them
// to *pbflow.Records instances, and submits them to the collector.
func (g *GRPCProto) ExportFlows(input <-chan []*model.Record) {
	socket := utils.GetSocket(g.hostIP, g.hostPort)
	log := glog.WithField("collector", socket)

	if g.reconnectTimer > 0 {
		ticker := time.NewTicker(g.reconnectTimer)
		log.Infof("Reconnect timer set to: %v", g.reconnectTimer)
		done := make(chan bool)
		defer func() {
			ticker.Stop()
			done <- true
		}()
		go func() {
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					// Re-establish the connection
					if err := g.reconnect(); err != nil {
						log.WithError(err).Warn("couldn't reconnect the GRPC export client")
						g.metrics.Errors.WithErrorName(componentGRPC, "CannotReconnectClient", metrics.HighSeverity).Inc()
					}
				}
			}
		}()
	}
	for inputRecords := range input {
		g.sendBatch(inputRecords, log)
	}
	if err := g.clientConn.Close(); err != nil {
		log.WithError(err).Warn("couldn't close flow export client")
		g.metrics.Errors.WithErrorName(componentGRPC, "CannotCloseClient", metrics.MediumSeverity).Inc()
	}
}

func (g *GRPCProto) sendBatch(batch []*model.Record, log *logrus.Entry) {
	g.m.RLock()
	defer g.m.RUnlock()
	g.metrics.EvictionCounter.WithSource(componentGRPC).Inc()
	for _, pbRecords := range pbflow.FlowsToPB(batch, g.maxFlowsPerMessage) {
		log.Debugf("sending %d records", len(pbRecords.Entries))
		if _, err := g.clientConn.Client().Send(context.TODO(), pbRecords); err != nil {
			g.metrics.Errors.WithErrorName(componentGRPC, "CannotWriteMessage", metrics.HighSeverity).Inc()
			log.WithError(err).Error("couldn't send flow records to collector")
		}
		g.batchCounterMetric.Inc()
		g.metrics.EvictedFlowsCounter.WithSource(componentGRPC).Add(float64(len(pbRecords.Entries)))
	}
}

func randomizeTimer(cfg *config.Agent) time.Duration {
	if cfg.GRPCReconnectTimer <= 0 {
		return 0
	}
	timer := cfg.GRPCReconnectTimer
	if cfg.GRPCReconnectTimerRandomization <= 0 || cfg.GRPCReconnectTimerRandomization >= timer {
		return timer
	}
	timer += time.Duration(rand.Int64N(2*int64(cfg.GRPCReconnectTimerRandomization)) - int64(cfg.GRPCReconnectTimerRandomization))
	if timer < 0 {
		return time.Second
	}
	return timer
}
