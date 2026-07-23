package agent

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/netobserv/gopipes/pkg/node"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/exporter"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/sirupsen/logrus"
)

// Packets reporting agent
type Packets struct {
	cfg *config.Agent

	informer ifaces.Informer
	ebpf     ebpfPacketFetcher

	perfTracer        *flow.PerfTracer
	packetbuffer      *flow.PerfBuffer
	plaintextTracer   *flow.PlaintextTracer
	plaintextBuffer   *flow.PlaintextBuffer
	plaintextExporter node.TerminalFunc[[]*model.PlaintextRecord]
	exporter          node.TerminalFunc[[]*model.PacketRecord]

	agentIP net.IP
	status  Status
}

type ebpfPacketFetcher interface {
	io.Closer
	tcAttacher
	LookupAndDeleteMap(*metrics.Metrics) map[int][]*byte
	ReadPerf() (ringbuf.Record, error)
	ReadSSLRingBuf() (ringbuf.Record, error)
}

// PacketsAgent instantiates a new agent, given a configuration.
func PacketsAgent(cfg *config.Agent) (*Packets, error) {
	plog.Info("initializing Packets agent")
	config.ManageDeprecatedConfigs(cfg)

	plog.Info("[PCA]acquiring Agent IP")
	agentIP, err := fetchAgentIP(cfg)
	if err != nil {
		return nil, fmt.Errorf("acquiring Agent IP: %w", err)
	}

	packetexportFunc, plaintextExportFunc, err := buildPacketExporters(cfg)
	if err != nil {
		return nil, err
	}

	ingress, egress := flowDirections(cfg)
	debug := cfg.LogLevel == logrus.TraceLevel.String() || cfg.LogLevel == logrus.DebugLevel.String()
	filterRules, err := parseFlowFilterRules(cfg.FlowFilterRules)
	if err != nil {
		return nil, err
	}

	ebpfConfig := &tracer.FlowFetcherConfig{
		Agent:         *cfg,
		EnableIngress: ingress,
		EnableEgress:  egress,
		Debug:         debug,
		FilterConfig:  filterRules,
	}

	fetcher, err := tracer.NewPacketFetcher(ebpfConfig)
	if err != nil {
		return nil, err
	}

	return packetsAgent(cfg, fetcher, fetcher.PlaintextScope(), packetexportFunc, plaintextExportFunc, agentIP)
}

func packetsAgent(
	cfg *config.Agent,
	fetcher ebpfPacketFetcher,
	plaintextProcessor flow.PlaintextProcessor,
	packetexporter node.TerminalFunc[[]*model.PacketRecord],
	plaintextExporter node.TerminalFunc[[]*model.PlaintextRecord],
	agentIP net.IP,
) (*Packets, error) {
	perfTracer := flow.NewPerfTracer(fetcher, cfg.CacheActiveTimeout)
	packetbuffer := flow.NewPerfBuffer(cfg.CacheMaxFlows, cfg.CacheActiveTimeout)
	informer := createInformer(cfg, metrics.NoOp())

	p := &Packets{
		ebpf:              fetcher,
		cfg:               cfg,
		packetbuffer:      packetbuffer,
		perfTracer:        perfTracer,
		informer:          informer,
		agentIP:           agentIP,
		exporter:          packetexporter,
		plaintextExporter: plaintextExporter,
	}

	if (cfg.EnableOpenSSLTracking || cfg.EnableGoTLSTracking || cfg.EnableKTLSTracking) && plaintextExporter == nil {
		return nil, fmt.Errorf("TLS plaintext capture requires export=direct-flp")
	}

	if cfg.EnableOpenSSLTracking || cfg.EnableGoTLSTracking || cfg.EnableKTLSTracking {
		p.plaintextTracer = flow.NewPlaintextTracer(fetcher, metrics.NoOp(), plaintextProcessor)
		p.plaintextBuffer = flow.NewPlaintextBuffer(cfg.CacheMaxFlows, cfg.CacheActiveTimeout)
	}

	return p, nil
}

func buildPacketExporters(cfg *config.Agent) (
	node.TerminalFunc[[]*model.PacketRecord],
	node.TerminalFunc[[]*model.PlaintextRecord],
	error,
) {
	switch cfg.Export {
	case "grpc":
		pkt, err := buildGRPCPacketExporter(cfg)
		if err != nil {
			return nil, nil, err
		}
		return pkt, nil, nil
	case "direct-flp":
		flpExporter, err := exporter.StartDirectFLP(cfg.FLPConfig, cfg.BuffersLength, cfg.TLSPlaintextPreviewBytes)
		if err != nil {
			return nil, nil, err
		}
		return flpExporter.ExportPackets, flpExporter.ExportPlaintext, nil
	default:
		return nil, nil, fmt.Errorf("unsupported packet export type %s", cfg.Export)
	}
}

func buildGRPCPacketExporter(cfg *config.Agent) (node.TerminalFunc[[]*model.PacketRecord], error) {
	if cfg.TargetHost == "" || cfg.TargetPort == 0 {
		return nil, fmt.Errorf("missing target host or port for PCA: %s:%d",
			cfg.TargetHost, cfg.TargetPort)
	}
	plog.Info("starting gRPC Packet send")
	pcapStreamer, err := exporter.StartGRPCPacketSend(cfg.TargetHost, cfg.TargetPort)
	if err != nil {
		return nil, err
	}
	return pcapStreamer.ExportGRPCPackets, nil
}

func (p *Packets) Run(ctx context.Context) error {
	p.status = StatusStarting
	plog.Info("Starting Packets agent")
	graph, err := p.buildAndStartPipeline(ctx)
	if err != nil {
		return fmt.Errorf("error starting processing graph: %w", err)
	}

	p.status = StatusStarted
	plog.Info("Packets agent successfully started")
	<-ctx.Done()

	p.status = StatusStopping
	plog.Info("stopping Packets agent")
	if err := p.ebpf.Close(); err != nil {
		plog.WithError(err).Warn("eBPF resources not correctly closed")
	}

	plog.Debug("waiting for all nodes to finish their pending work")
	<-graph.Done()

	p.status = StatusStopped
	plog.Info("Packets agent stopped")
	return nil
}

func (p *Packets) Status() Status {
	return p.status
}

func (p *Packets) buildAndStartPipeline(ctx context.Context) (*node.Terminal[[]*model.PacketRecord], error) {
	if !p.cfg.EbpfProgramManagerMode {
		plog.Debug("registering interfaces' listener in background")
		err := startInterfaceListener(ctx, p.ebpf, p.cfg, metrics.NoOp(), p.informer)
		if err != nil {
			return nil, err
		}
	}

	ebl := p.cfg.ExporterBufferLength
	if ebl == 0 {
		ebl = p.cfg.BuffersLength
	}

	perfTracer := node.AsStart(p.perfTracer.TraceLoop(ctx))
	packetbuffer := node.AsMiddle(p.packetbuffer.PBuffer, node.ChannelBufferLen(p.cfg.BuffersLength))
	export := node.AsTerminal(p.exporter, node.ChannelBufferLen(ebl))
	perfTracer.SendsTo(packetbuffer)
	packetbuffer.SendsTo(export)
	perfTracer.Start()

	if p.plaintextTracer != nil && p.plaintextExporter != nil {
		ptTracer := node.AsStart(p.plaintextTracer.TraceLoop(ctx))
		ptBuffer := node.AsMiddle(p.plaintextBuffer.PBuffer, node.ChannelBufferLen(p.cfg.BuffersLength))
		ptExport := node.AsTerminal(p.plaintextExporter, node.ChannelBufferLen(ebl))
		ptTracer.SendsTo(ptBuffer)
		ptBuffer.SendsTo(ptExport)
		ptTracer.Start()
	}

	return export, nil
}
