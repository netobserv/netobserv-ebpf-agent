package flows

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/netobserv/gopipes/pkg/node"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/agent/common"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	exporterflows "github.com/netobserv/netobserv-ebpf-agent/pkg/exporter/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/kernel"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	promo "github.com/netobserv/netobserv-ebpf-agent/pkg/prometheus"
	tracerflows "github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/flows"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/gavv/monotime"
	ovnobserv "github.com/ovn-org/ovn-kubernetes/go-controller/observability-lib/sampledecoder"
	kafkago "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/compress"
	"github.com/sirupsen/logrus"
)

var alog = logrus.WithField("component", "agent.Flows")

const (
	networkEventsDBPath    = "/var/run/ovn/ovnnb_db.sock"
	networkEventsOwnerName = "netobservAgent"
)

// Flows reporting agent
type Agent struct {
	cfg *config.Agent

	// input data providers
	informer ifaces.Informer
	ebpf     ebpfFlowFetcher

	// processing nodes to be wired in the buildAndStartPipeline method
	mapTracer *flow.MapTracer
	rbTracer  *flow.RingBufTracer
	accounter *flow.Accounter
	limiter   *flow.CapacityLimiter
	exporter  node.TerminalFunc[[]*model.Record]

	status        common.Status
	promoServer   *http.Server
	sampleDecoder *ovnobserv.SampleDecoder

	metrics     *metrics.Metrics
	rbSSLTracer *flow.RingBufTracer
}

// ebpfFlowFetcher abstracts the interface of ebpf.FlowFetcher to allow dependency injection in tests
type ebpfFlowFetcher interface {
	io.Closer
	common.TCAttacher

	LookupAndDeleteMap(*metrics.Metrics) map[ebpf.BpfFlowId]model.BpfFlowContent
	DeleteMapsStaleEntries(timeOut time.Duration)
	ReadRingBuf() (ringbuf.Record, error)
	ReadSSLRingBuf() (ringbuf.Record, error)
}

// New instantiates a new flow agent from configuration.
func New(cfg *config.Agent) (*Agent, error) {
	alog.Info("initializing Flows agent")

	// manage deprecated configs
	config.ManageDeprecatedConfigs(cfg)

	alog.Debug("acquiring Agent IP")
	agentIP, err := common.FetchAgentIP(cfg)
	if err != nil {
		return nil, fmt.Errorf("acquiring Agent IP: %w", err)
	}
	alog.Debug("agent IP: " + agentIP.String())

	// initialize metrics
	metricsSettings := &metrics.Settings{
		PromConnectionInfo: metrics.PromConnectionInfo{
			Address: cfg.MetricsServerAddress,
			Port:    cfg.MetricsPort,
		},
		Prefix: cfg.MetricsPrefix,
		Level:  metrics.Level(cfg.MetricsLevel),
	}
	if cfg.MetricsTLSCertPath != "" && cfg.MetricsTLSKeyPath != "" {
		metricsSettings.PromConnectionInfo.TLS = &metrics.PromTLS{
			CertPath: cfg.MetricsTLSCertPath,
			KeyPath:  cfg.MetricsTLSKeyPath,
		}
	}
	m := metrics.NewMetrics(metricsSettings)

	var s *ovnobserv.SampleDecoder
	if cfg.Flows.EnableNetworkEventsMonitoring || cfg.Flows.EnableUDNMapping {
		if !kernel.IsKernelOlderThan("5.14.0") {
			if s, err = ovnobserv.NewSampleDecoderWithDefaultCollector(context.Background(), networkEventsDBPath,
				networkEventsOwnerName, cfg.Flows.NetworkEventsMonitoringGroupID); err != nil {
				alog.Warnf("failed to create Network Events sample decoder: %v for id: %d", err, cfg.Flows.NetworkEventsMonitoringGroupID)
			} else {
				alog.Info("Network Events sample decoder successfully created")
			}
		} else {
			alog.Warn("old kernel doesn't support network events monitoring skip")
		}
	}

	// configure selected exporter
	exportFunc, err := buildFlowExporter(cfg, m)
	if err != nil {
		return nil, err
	}

	ingress, egress := common.FlowDirections(cfg)
	debug := cfg.LogLevel == logrus.TraceLevel.String() || cfg.LogLevel == logrus.DebugLevel.String()

	filterRules, err := common.ParseFlowFilterRules(cfg.FlowFilterRules)
	if err != nil {
		return nil, err
	}

	ebpfConfig := &tracerflows.FetcherConfig{
		Agent:         *cfg,
		EnableIngress: ingress,
		EnableEgress:  egress,
		Debug:         debug,
		FilterConfig:  filterRules,
	}

	fetcher, err := tracerflows.NewFetcher(ebpfConfig, m)
	if err != nil {
		return nil, err
	}

	return newAgent(cfg, m, fetcher, exportFunc, agentIP, s)
}

// newAgent is a private constructor with injectable dependencies, usable for tests.
func newAgent(
	cfg *config.Agent,
	m *metrics.Metrics,
	fetcher ebpfFlowFetcher,
	exporter node.TerminalFunc[[]*model.Record],
	agentIP net.IP,
	s *ovnobserv.SampleDecoder,
) (*Agent, error) {
	model.SetGlobalIP(agentIP)

	var promoServer *http.Server
	if cfg.MetricsEnable {
		promoServer = promo.InitializePrometheus(m.Settings)
	}

	samplingGauge := m.CreateSamplingRate()
	samplingGauge.Set(float64(cfg.Sampling))

	mapTracer := flow.NewMapTracer(fetcher, cfg.CacheActiveTimeout, cfg.Flows.StaleEntriesEvictTimeout, m, s, cfg.Flows.EnableUDNMapping)
	var rbTracer *flow.RingBufTracer
	if cfg.Flows.EnableFlowsRingbufFallback {
		rbTracer = flow.NewRingBufTracer(fetcher, mapTracer, cfg.CacheActiveTimeout, m)
	}
	var rbSSLTracer *flow.RingBufTracer
	if cfg.EnableOpenSSLTracking {
		rbSSLTracer = flow.NewSSLRingBufTracer(fetcher, mapTracer, cfg.CacheActiveTimeout, m)
	}

	var accounter *flow.Accounter
	if rbTracer != nil || rbSSLTracer != nil {
		accounter = flow.NewAccounter(cfg.CacheMaxFlows, cfg.CacheActiveTimeout, time.Now, monotime.Now, m, s, cfg.Flows.EnableUDNMapping)
	}
	limiter := flow.NewCapacityLimiter(m)

	informer := common.CreateInformer(cfg, m)

	return &Agent{
		ebpf:          fetcher,
		exporter:      exporter,
		cfg:           cfg,
		mapTracer:     mapTracer,
		rbTracer:      rbTracer,
		accounter:     accounter,
		limiter:       limiter,
		informer:      informer,
		promoServer:   promoServer,
		metrics:       m,
		rbSSLTracer:   rbSSLTracer,
		sampleDecoder: s,
	}, nil
}

func buildFlowExporter(cfg *config.Agent, m *metrics.Metrics) (node.TerminalFunc[[]*model.Record], error) {
	switch cfg.Export {
	case "grpc":
		return buildGRPCExporter(cfg, m)
	case "kafka":
		return buildKafkaExporter(cfg, m)
	case "ipfix+udp":
		return buildIPFIXExporter(cfg, "udp")
	case "ipfix+tcp":
		return buildIPFIXExporter(cfg, "tcp")
	case "direct-flp":
		return buildFlowDirectFLPExporter(cfg)
	default:
		return nil, fmt.Errorf("wrong flow export type %s", cfg.Export)
	}
}

func buildGRPCExporter(cfg *config.Agent, m *metrics.Metrics) (node.TerminalFunc[[]*model.Record], error) {
	if cfg.TargetHost == "" || cfg.TargetPort == 0 {
		return nil, fmt.Errorf("missing target host or port: %s:%d",
			cfg.TargetHost, cfg.TargetPort)
	}
	grpcExporter, err := exporterflows.StartGRPCProto(cfg, m)
	if err != nil {
		return nil, err
	}
	return grpcExporter.ExportFlows, nil
}

func buildFlowDirectFLPExporter(cfg *config.Agent) (node.TerminalFunc[[]*model.Record], error) {
	flpExporter, err := exporterflows.StartDirectFLP(cfg.FLPConfig, cfg.BuffersLength, 0)
	if err != nil {
		return nil, err
	}
	return flpExporter.ExportFlows, nil
}

func buildKafkaExporter(cfg *config.Agent, m *metrics.Metrics) (node.TerminalFunc[[]*model.Record], error) {
	if len(cfg.Flows.KafkaBrokers) == 0 {
		return nil, errors.New("at least one Kafka broker is needed")
	}
	var compression compress.Compression
	if err := compression.UnmarshalText([]byte(cfg.Flows.KafkaCompression)); err != nil {
		return nil, fmt.Errorf("wrong Kafka compression value %s. Admitted values are "+
			"none, gzip, snappy, lz4, zstd: %w", cfg.Flows.KafkaCompression, err)
	}
	transport := kafkago.Transport{}
	if cfg.Flows.KafkaEnableTLS {
		tlsConfig, err := common.BuildTLSConfig(cfg)
		if err != nil {
			return nil, err
		}
		transport.TLS = tlsConfig
	}
	if cfg.Flows.KafkaEnableSASL {
		mechanism, err := common.BuildSASLConfig(cfg)
		if err != nil {
			return nil, err
		}
		transport.SASL = mechanism
	}
	return (&exporterflows.KafkaProto{
		Writer: &kafkago.Writer{
			Addr:      kafkago.TCP(cfg.Flows.KafkaBrokers...),
			Topic:     cfg.Flows.KafkaTopic,
			BatchSize: cfg.Flows.KafkaBatchMessages,
			// Assigning KafkaBatchSize to BatchBytes instead of BatchSize might be confusing here.
			// The reason is that the "standard" Kafka name for this variable is "batch.size",
			// which specifies the size of messages in terms of bytes, and not in terms of entries.
			// We have decided to hide this library implementation detail and expose to the
			// customer the common, standard name and meaning for batch.size
			BatchBytes: int64(cfg.Flows.KafkaBatchSize),
			// Segmentio's Kafka-go does not behave as standard Kafka library, and would
			// throttle any Write invocation until reaching the timeout.
			// Since we invoke write once each CacheActiveTimeout, we can safely disable this
			// timeout throttling
			// https://github.com/netobserv/flowlogs-pipeline/pull/233#discussion_r897830057
			BatchTimeout: time.Nanosecond,
			Async:        cfg.Flows.KafkaAsync,
			Compression:  compression,
			Transport:    &transport,
			Balancer:     &kafkago.Hash{},
		},
		Metrics: m,
	}).ExportFlows, nil
}

func buildIPFIXExporter(cfg *config.Agent, proto string) (node.TerminalFunc[[]*model.Record], error) {
	if cfg.TargetHost == "" || cfg.TargetPort == 0 {
		return nil, fmt.Errorf("missing target host or port: %s:%d",
			cfg.TargetHost, cfg.TargetPort)
	}
	ipfix, err := exporterflows.StartIPFIXExporter(cfg.TargetHost, cfg.TargetPort, proto)
	if err != nil {
		return nil, err
	}
	return ipfix.ExportFlows, nil
}

// Run a Flows agent. The function will keep running in the same thread
// until the passed context is canceled
func (a *Agent) Run(ctx context.Context) error {
	a.status = common.StatusStarting
	alog.Info("starting Flows agent")
	graph, err := a.buildAndStartPipeline(ctx)
	if err != nil {
		return fmt.Errorf("starting processing graph: %w", err)
	}

	a.status = common.StatusStarted
	alog.Info("Flows agent successfully started")
	<-ctx.Done()

	a.status = common.StatusStopping
	alog.Info("stopping Flows agent")
	if err := a.ebpf.Close(); err != nil {
		alog.WithError(err).Warn("eBPF resources not correctly closed")
	}

	alog.Debug("waiting for all nodes to finish their pending work")
	<-graph.Done()
	if a.promoServer != nil {
		alog.Debug("closing prometheus server")
		if err := a.promoServer.Close(); err != nil {
			alog.WithError(err).Warn("error when closing prometheus server")
		}
	}
	if a.sampleDecoder != nil {
		a.sampleDecoder.Shutdown()
	}
	a.status = common.StatusStopped
	alog.Info("Flows agent stopped")
	return nil
}

func (a *Agent) Status() common.Status {
	return a.status
}

// buildAndStartPipeline creates the ETL flow processing graph.
// For a more visual view, check the docs/architecture.md document.
func (a *Agent) buildAndStartPipeline(ctx context.Context) (*node.Terminal[[]*model.Record], error) {

	if !a.cfg.EbpfProgramManagerMode {
		alog.Debug("registering interfaces listener in background")
		err := common.StartInterfaceListener(ctx, a.ebpf, a.cfg, a.metrics, a.informer)
		if err != nil {
			return nil, err
		}
	}
	alog.Debug("connecting flows processing graph")
	mapTracer := node.AsStart(a.mapTracer.TraceLoop(ctx, a.cfg.Flows.ForceGC))
	var rbTracer, rbSSLTracer *node.Start[*model.RawRecord]
	if a.rbTracer != nil {
		rbTracer = node.AsStart(a.rbTracer.TraceLoop(ctx))
	}
	if a.rbSSLTracer != nil {
		rbSSLTracer = node.AsStart(a.rbSSLTracer.TraceLoop(ctx))
	}

	var accounter *node.Middle[*model.RawRecord, []*model.Record]
	if a.accounter != nil {
		accounter = node.AsMiddle(a.accounter.Account, node.ChannelBufferLen(a.cfg.BuffersLength))
	}

	limiter := node.AsMiddle(a.limiter.Limit, node.ChannelBufferLen(a.cfg.BuffersLength))

	ebl := a.cfg.ExporterBufferLength
	if ebl == 0 {
		ebl = a.cfg.BuffersLength
	}

	export := node.AsTerminal(a.exporter, node.ChannelBufferLen(ebl))

	if rbTracer != nil && accounter != nil {
		rbTracer.SendsTo(accounter)
	}
	if rbSSLTracer != nil && accounter != nil {
		rbSSLTracer.SendsTo(accounter)
	}

	mapTracer.SendsTo(limiter)
	if accounter != nil {
		accounter.SendsTo(limiter)
	}
	limiter.SendsTo(export)

	alog.Debug("starting graph")
	mapTracer.Start()
	if rbTracer != nil {
		rbTracer.Start()
	}
	if rbSSLTracer != nil {
		rbSSLTracer.Start()
	}
	return export, nil
}
