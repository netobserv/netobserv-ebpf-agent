package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/netobserv/gopipes/pkg/node"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/exporter"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/kernel"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	promo "github.com/netobserv/netobserv-ebpf-agent/pkg/prometheus"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/gavv/monotime"
	ovnobserv "github.com/ovn-org/ovn-kubernetes/go-controller/observability-lib/sampledecoder"
	kafkago "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/compress"
	"github.com/sirupsen/logrus"
)

var alog = logrus.WithField("component", "agent.Flows")
var plog = logrus.WithField("component", "agent.Packets")

// Status of the agent service. Helps on the health report as well as making some asynchronous
// tests waiting for the agent to accept flows.
type Status int

const (
	StatusNotStarted Status = iota
	StatusStarting
	StatusStarted
	StatusStopping
	StatusStopped
)

const (
	networkEventsDBPath    = "/var/run/ovn/ovnnb_db.sock"
	networkEventsOwnerName = "netobservAgent"
)

func (s Status) String() string {
	switch s {
	case StatusNotStarted:
		return "StatusNotStarted"
	case StatusStarting:
		return "StatusStarting"
	case StatusStarted:
		return "StatusStarted"
	case StatusStopping:
		return "StatusStopping"
	case StatusStopped:
		return "StatusStopped"
	default:
		return "invalid"
	}
}

func configureInformer(cfg *config.Agent, log *logrus.Entry) ifaces.Informer {
	var informer ifaces.Informer
	switch cfg.ListenInterfaces {
	case config.ListenPoll:
		log.WithField("period", cfg.ListenPollPeriod).
			Debug("listening for new interfaces: use polling")
		informer = ifaces.NewPoller(cfg.ListenPollPeriod, cfg.BuffersLength)
	case config.ListenWatch:
		log.Debug("listening for new interfaces: use watching")
		informer = ifaces.NewWatcher(cfg.BuffersLength)
	default:
		log.WithField("providedValue", cfg.ListenInterfaces).
			Warn("wrong interface listen method. Using file watcher as default")
		informer = ifaces.NewWatcher(cfg.BuffersLength)
	}
	return informer

}

func interfaceListener(ctx context.Context, ifaceEvents <-chan ifaces.Event, slog *logrus.Entry, processEvent func(iface *ifaces.Interface, add bool)) {
	for {
		select {
		case <-ctx.Done():
			slog.Debug("stopping interfaces' listener")
			return
		case event := <-ifaceEvents:
			slog.WithField("event", event).Debug("received event")
			switch event.Type {
			case ifaces.EventAdded:
				processEvent(event.Interface, true)
			case ifaces.EventDeleted:
				processEvent(event.Interface, false)
			default:
				slog.WithField("event", event).Warn("unknown event type")
			}
		}
	}
}

// Flows reporting agent
type Flows struct {
	cfg *config.Agent

	// input data providers
	interfaces ifaces.Informer
	filter     ifaces.Filter
	ebpf       ebpfFlowFetcher

	// processing nodes to be wired in the buildAndStartPipeline method
	mapTracer *flow.MapTracer
	rbTracer  *flow.RingBufTracer
	accounter *flow.Accounter
	limiter   *flow.CapacityLimiter
	exporter  node.TerminalFunc[[]*model.Record]

	status        Status
	promoServer   *http.Server
	sampleDecoder *ovnobserv.SampleDecoder

	metrics *metrics.Metrics
}

// ebpfFlowFetcher abstracts the interface of ebpf.FlowFetcher to allow dependency injection in tests
type ebpfFlowFetcher interface {
	io.Closer
	Register(iface *ifaces.Interface) error
	UnRegister(iface *ifaces.Interface) error
	AttachTCX(iface *ifaces.Interface) error
	DetachTCX(iface *ifaces.Interface) error

	LookupAndDeleteMap(*metrics.Metrics) map[ebpf.BpfFlowId]model.BpfFlowContent
	DeleteMapsStaleEntries(timeOut time.Duration)
	ReadRingBuf() (ringbuf.Record, error)
}

// FlowsAgent instantiates a new agent, given a configuration.
func FlowsAgent(cfg *config.Agent) (*Flows, error) {
	alog.Info("initializing Flows agent")

	// manage deprecated configs
	config.ManageDeprecatedConfigs(cfg)

	// configure informer for new interfaces
	informer := configureInformer(cfg, alog)

	alog.Debug("acquiring Agent IP")
	agentIP, err := fetchAgentIP(cfg)
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
	if cfg.EnableNetworkEventsMonitoring || cfg.EnableUDNMapping {
		if !kernel.IsKernelOlderThan("5.14.0") {
			if s, err = ovnobserv.NewSampleDecoderWithDefaultCollector(context.Background(), networkEventsDBPath,
				networkEventsOwnerName, cfg.NetworkEventsMonitoringGroupID); err != nil {
				alog.Warnf("failed to create Network Events sample decoder: %v for id: %d", err, cfg.NetworkEventsMonitoringGroupID)
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

	ingress, egress := flowDirections(cfg)
	debug := false
	if cfg.LogLevel == logrus.TraceLevel.String() || cfg.LogLevel == logrus.DebugLevel.String() {
		debug = true
	}
	filterRules := make([]*tracer.FilterConfig, 0)
	if cfg.EnableFlowFilter {
		var flowFilters []*config.FlowFilter
		if err := json.Unmarshal([]byte(cfg.FlowFilterRules), &flowFilters); err != nil {
			return nil, err
		}

		for _, r := range flowFilters {
			filterRules = append(filterRules, &tracer.FilterConfig{
				Action:          r.Action,
				Direction:       r.Direction,
				IPCIDR:          r.IPCIDR,
				Protocol:        r.Protocol,
				PeerIP:          r.PeerIP,
				PeerCIDR:        r.PeerCIDR,
				DestinationPort: tracer.ConvertFilterPortsToInstr(r.DestinationPort, r.DestinationPortRange, r.DestinationPorts),
				SourcePort:      tracer.ConvertFilterPortsToInstr(r.SourcePort, r.SourcePortRange, r.SourcePorts),
				Port:            tracer.ConvertFilterPortsToInstr(r.Port, r.PortRange, r.Ports),
				TCPFlags:        r.TCPFlags,
				Drops:           r.Drops,
				Sample:          r.Sample,
			})
		}
	}
	ebpfConfig := &tracer.FlowFetcherConfig{
		EnableIngress:                  ingress,
		EnableEgress:                   egress,
		Debug:                          debug,
		Sampling:                       cfg.Sampling,
		CacheMaxSize:                   cfg.CacheMaxFlows,
		EnablePktDrops:                 cfg.EnablePktDrops,
		EnableDNSTracker:               cfg.EnableDNSTracking,
		DNSTrackerPort:                 cfg.DNSTrackingPort,
		EnableRTT:                      cfg.EnableRTT,
		EnableNetworkEventsMonitoring:  cfg.EnableNetworkEventsMonitoring,
		NetworkEventsMonitoringGroupID: cfg.NetworkEventsMonitoringGroupID,
		EnableFlowFilter:               cfg.EnableFlowFilter,
		EnablePktTranslation:           cfg.EnablePktTranslationTracking,
		UseEbpfManager:                 cfg.EbpfProgramManagerMode,
		BpfManBpfFSPath:                cfg.BpfManBpfFSPath,
		EnableIPsecTracker:             cfg.EnableIPsecTracking,
		FilterConfig:                   filterRules,
	}

	fetcher, err := tracer.NewFlowFetcher(ebpfConfig)
	if err != nil {
		return nil, err
	}

	return flowsAgent(cfg, m, informer, fetcher, exportFunc, agentIP, s)
}

// flowsAgent is a private constructor with injectable dependencies, usable for tests
func flowsAgent(
	cfg *config.Agent,
	m *metrics.Metrics,
	informer ifaces.Informer,
	fetcher ebpfFlowFetcher,
	exporter node.TerminalFunc[[]*model.Record],
	agentIP net.IP,
	s *ovnobserv.SampleDecoder,
) (*Flows, error) {

	filter, err := ifaces.FromConfig(cfg)
	if err != nil {
		return nil, err
	}
	registerer, err := ifaces.NewRegisterer(informer, cfg, m)
	if err != nil {
		return nil, err
	}

	interfaceNamer := func(ifIndex int, mac model.MacAddr) string {
		iface, ok := registerer.IfaceNameForIndexAndMAC(ifIndex, mac)
		if !ok {
			return "unknown"
		}
		return iface
	}
	model.SetGlobals(agentIP, interfaceNamer)

	var promoServer *http.Server
	if cfg.MetricsEnable {
		promoServer = promo.InitializePrometheus(m.Settings)
	}

	samplingGauge := m.CreateSamplingRate()
	samplingGauge.Set(float64(cfg.Sampling))

	mapTracer := flow.NewMapTracer(fetcher, cfg.CacheActiveTimeout, cfg.StaleEntriesEvictTimeout, m, s, cfg.EnableUDNMapping)
	rbTracer := flow.NewRingBufTracer(fetcher, mapTracer, cfg.CacheActiveTimeout, m)
	accounter := flow.NewAccounter(cfg.CacheMaxFlows, cfg.CacheActiveTimeout, time.Now, monotime.Now, m, s, cfg.EnableUDNMapping)
	limiter := flow.NewCapacityLimiter(m)

	return &Flows{
		ebpf:        fetcher,
		exporter:    exporter,
		interfaces:  registerer,
		filter:      filter,
		cfg:         cfg,
		mapTracer:   mapTracer,
		rbTracer:    rbTracer,
		accounter:   accounter,
		limiter:     limiter,
		promoServer: promoServer,
		metrics:     m,
	}, nil
}

func flowDirections(cfg *config.Agent) (ingress, egress bool) {
	switch cfg.Direction {
	case config.DirectionIngress:
		return true, false
	case config.DirectionEgress:
		return false, true
	case config.DirectionBoth:
		return true, true
	default:
		alog.Warnf("unknown DIRECTION %q. Tracing both ingress and egress traffic", cfg.Direction)
		return true, true
	}
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
	grpcExporter, err := exporter.StartGRPCProto(cfg.TargetHost, cfg.TargetPort, cfg.GRPCMessageMaxFlows, m)
	if err != nil {
		return nil, err
	}
	return grpcExporter.ExportFlows, nil
}

func buildFlowDirectFLPExporter(cfg *config.Agent) (node.TerminalFunc[[]*model.Record], error) {
	flpExporter, err := exporter.StartDirectFLP(cfg.FLPConfig, cfg.BuffersLength)
	if err != nil {
		return nil, err
	}
	return flpExporter.ExportFlows, nil
}

func buildKafkaExporter(cfg *config.Agent, m *metrics.Metrics) (node.TerminalFunc[[]*model.Record], error) {
	if len(cfg.KafkaBrokers) == 0 {
		return nil, errors.New("at least one Kafka broker is needed")
	}
	var compression compress.Compression
	if err := compression.UnmarshalText([]byte(cfg.KafkaCompression)); err != nil {
		return nil, fmt.Errorf("wrong Kafka compression value %s. Admitted values are "+
			"none, gzip, snappy, lz4, zstd: %w", cfg.KafkaCompression, err)
	}
	transport := kafkago.Transport{}
	if cfg.KafkaEnableTLS {
		tlsConfig, err := buildTLSConfig(cfg)
		if err != nil {
			return nil, err
		}
		transport.TLS = tlsConfig
	}
	if cfg.KafkaEnableSASL {
		mechanism, err := buildSASLConfig(cfg)
		if err != nil {
			return nil, err
		}
		transport.SASL = mechanism
	}
	return (&exporter.KafkaProto{
		Writer: &kafkago.Writer{
			Addr:      kafkago.TCP(cfg.KafkaBrokers...),
			Topic:     cfg.KafkaTopic,
			BatchSize: cfg.KafkaBatchMessages,
			// Assigning KafkaBatchSize to BatchBytes instead of BatchSize might be confusing here.
			// The reason is that the "standard" Kafka name for this variable is "batch.size",
			// which specifies the size of messages in terms of bytes, and not in terms of entries.
			// We have decided to hide this library implementation detail and expose to the
			// customer the common, standard name and meaning for batch.size
			BatchBytes: int64(cfg.KafkaBatchSize),
			// Segmentio's Kafka-go does not behave as standard Kafka library, and would
			// throttle any Write invocation until reaching the timeout.
			// Since we invoke write once each CacheActiveTimeout, we can safely disable this
			// timeout throttling
			// https://github.com/netobserv/flowlogs-pipeline/pull/233#discussion_r897830057
			BatchTimeout: time.Nanosecond,
			Async:        cfg.KafkaAsync,
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
	ipfix, err := exporter.StartIPFIXExporter(cfg.TargetHost, cfg.TargetPort, proto)
	if err != nil {
		return nil, err
	}
	return ipfix.ExportFlows, nil
}

// Run a Flows agent. The function will keep running in the same thread
// until the passed context is canceled
func (f *Flows) Run(ctx context.Context) error {
	f.status = StatusStarting
	alog.Info("starting Flows agent")
	graph, err := f.buildAndStartPipeline(ctx)
	if err != nil {
		return fmt.Errorf("starting processing graph: %w", err)
	}

	f.status = StatusStarted
	alog.Info("Flows agent successfully started")
	<-ctx.Done()

	f.status = StatusStopping
	alog.Info("stopping Flows agent")
	if err := f.ebpf.Close(); err != nil {
		alog.WithError(err).Warn("eBPF resources not correctly closed")
	}

	alog.Debug("waiting for all nodes to finish their pending work")
	<-graph.Done()
	if f.promoServer != nil {
		alog.Debug("closing prometheus server")
		if err := f.promoServer.Close(); err != nil {
			alog.WithError(err).Warn("error when closing prometheus server")
		}
	}
	if f.sampleDecoder != nil {
		f.sampleDecoder.Shutdown()
	}
	f.status = StatusStopped
	alog.Info("Flows agent stopped")
	return nil
}

func (f *Flows) Status() Status {
	return f.status
}

// interfacesManager uses an informer to check new/deleted network interfaces. For each running
// interface, it registers a flow ebpfFetcher that will forward new flows to the returned channel
// TODO: consider move this method and "onInterfaceEvent" to another type
func (f *Flows) interfacesManager(ctx context.Context) error {
	slog := alog.WithField("function", "interfacesManager")

	slog.Debug("subscribing for network interface events")
	ifaceEvents, err := f.interfaces.Subscribe(ctx)
	if err != nil {
		return fmt.Errorf("instantiating interfaces' informer: %w", err)
	}

	go interfaceListener(ctx, ifaceEvents, slog, f.onInterfaceEvent)

	return nil
}

// buildAndStartPipeline creates the ETL flow processing graph.
// For a more visual view, check the docs/architecture.md document.
func (f *Flows) buildAndStartPipeline(ctx context.Context) (*node.Terminal[[]*model.Record], error) {

	if !f.cfg.EbpfProgramManagerMode {
		alog.Debug("registering interfaces' listener in background")
		err := f.interfacesManager(ctx)
		if err != nil {
			return nil, err
		}
	}
	alog.Debug("connecting flows' processing graph")
	mapTracer := node.AsStart(f.mapTracer.TraceLoop(ctx, f.cfg.ForceGC))
	rbTracer := node.AsStart(f.rbTracer.TraceLoop(ctx))

	accounter := node.AsMiddle(f.accounter.Account,
		node.ChannelBufferLen(f.cfg.BuffersLength))

	limiter := node.AsMiddle(f.limiter.Limit,
		node.ChannelBufferLen(f.cfg.BuffersLength))

	ebl := f.cfg.ExporterBufferLength
	if ebl == 0 {
		ebl = f.cfg.BuffersLength
	}

	export := node.AsTerminal(f.exporter,
		node.ChannelBufferLen(ebl))

	rbTracer.SendsTo(accounter)

	mapTracer.SendsTo(limiter)
	accounter.SendsTo(limiter)
	limiter.SendsTo(export)

	alog.Debug("starting graph")
	mapTracer.Start()
	rbTracer.Start()
	return export, nil
}

func (f *Flows) onInterfaceEvent(iface *ifaces.Interface, add bool) {
	// ignore interfaces that do not match the user configuration acceptance/exclusion lists
	allowed, err := f.filter.Allowed(iface.Name)
	if err != nil {
		alog.WithField("interface", iface).Errorf("encountered error determining if interface is allowed: %v", err)
		return
	}
	if !allowed {
		alog.WithField("interface", iface).
			Debug("interface does not match the allow/exclusion filters. Ignoring")
		return
	}
	if add {
		if err1 := f.ebpf.AttachTCX(iface); err1 != nil {
			if err2 := f.ebpf.Register(iface); err2 != nil {
				alog.WithField("interface", iface).WithError(err2).Warn("interface detected, could not attach any hook")
				f.metrics.InterfaceEventsCounter.Increase("attach_fail", iface.Name, iface.Index, iface.NSName, iface.MAC)
				return
			}
			iface.HookType = ifaces.TCHook
			alog.WithField("interface", iface).WithError(err1).Debug("interface detected, could not attach TCX hook, falling back to legacy TC")
			f.metrics.InterfaceEventsCounter.Increase("attach_tc", iface.Name, iface.Index, iface.NSName, iface.MAC)
			return
		}
		iface.HookType = ifaces.TCXHook
		alog.WithField("interface", iface).Debug("interface detected, TCX hook attached")
		f.metrics.InterfaceEventsCounter.Increase("attach_tcx", iface.Name, iface.Index, iface.NSName, iface.MAC)
	} else {
		switch iface.HookType {
		case ifaces.TCHook:
			if err := f.ebpf.UnRegister(iface); err != nil {
				alog.WithField("interface", iface).WithError(err).Warn("interface deleted, could not detach TC hook")
				f.metrics.InterfaceEventsCounter.Increase("detach_tc_fail", iface.Name, iface.Index, iface.NSName, iface.MAC)
				f.metrics.Errors.WithErrorName("InterfaceEvents", "CantDetachTC", metrics.HighSeverity).Inc()
				return
			}
			alog.WithField("interface", iface).Debug("interface deleted, TC hook detached")
			f.metrics.InterfaceEventsCounter.Increase("detach_tc", iface.Name, iface.Index, iface.NSName, iface.MAC)
		case ifaces.TCXHook:
			if err := f.ebpf.DetachTCX(iface); err != nil {
				alog.WithField("interface", iface).WithError(err).Warn("interface deleted, could not detach TCX hook")
				f.metrics.InterfaceEventsCounter.Increase("detach_tcx_fail", iface.Name, iface.Index, iface.NSName, iface.MAC)
				f.metrics.Errors.WithErrorName("InterfaceEvents", "CantDetachTCX", metrics.HighSeverity).Inc()
				return
			}
			alog.WithField("interface", iface).Debug("interface deleted, TCX hook detached")
			f.metrics.InterfaceEventsCounter.Increase("detach_tcx", iface.Name, iface.Index, iface.NSName, iface.MAC)
		case ifaces.Unset:
			alog.WithField("interface", iface).Warn("interface deleted and no known hook attached, trying to detach anyway...")
			if err1 := f.ebpf.DetachTCX(iface); err1 != nil {
				if err2 := f.ebpf.UnRegister(iface); err2 != nil {
					alog.WithField("interface", iface).WithError(err2).Warn("interface deleted, could not detach any hook")
					f.metrics.InterfaceEventsCounter.Increase("unset_detach_fail", iface.Name, iface.Index, iface.NSName, iface.MAC)
					return
				}
				alog.WithField("interface", iface).WithError(err1).Debug("interface deleted, could not detach TCX hook, falling back to legacy TC")
				f.metrics.InterfaceEventsCounter.Increase("unset_detach_tc", iface.Name, iface.Index, iface.NSName, iface.MAC)
				return
			}
			alog.WithField("interface", iface).Debug("interface deleted, TCX hook detached")
			f.metrics.InterfaceEventsCounter.Increase("unset_detach_tcx", iface.Name, iface.Index, iface.NSName, iface.MAC)
		}
	}
}
