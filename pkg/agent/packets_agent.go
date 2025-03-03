package agent

import (
	"context"
	"encoding/json"
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

	// input data providers
	informer ifaces.Informer
	ebpf     ebpfPacketFetcher

	// processing nodes to be wired in the buildAndStartPipeline method
	perfTracer   *flow.PerfTracer
	packetbuffer *flow.PerfBuffer
	exporter     node.TerminalFunc[[]*model.PacketRecord]

	// elements used to decorate flows with extra information
	agentIP net.IP

	status Status
}

type ebpfPacketFetcher interface {
	io.Closer
	tcAttacher
	LookupAndDeleteMap(*metrics.Metrics) map[int][]*byte
	ReadPerf() (ringbuf.Record, error)
}

// PacketsAgent instantiates a new agent, given a configuration.
func PacketsAgent(cfg *config.Agent) (*Packets, error) {
	plog.Info("initializing Packets agent")

	// manage deprecated configs
	config.ManageDeprecatedConfigs(cfg)

	plog.Info("[PCA]acquiring Agent IP")
	agentIP, err := fetchAgentIP(cfg)
	if err != nil {
		return nil, fmt.Errorf("acquiring Agent IP: %w", err)
	}

	// configure selected exporter
	packetexportFunc, err := buildPacketExporter(cfg)
	if err != nil {
		return nil, err
	}

	ingress, egress := flowDirections(cfg)
	debug := cfg.LogLevel == logrus.TraceLevel.String() || cfg.LogLevel == logrus.DebugLevel.String()
	filterRules := make([]*tracer.FilterConfig, 0)
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
	ebpfConfig := &tracer.FlowFetcherConfig{
		EnableIngress:  ingress,
		EnableEgress:   egress,
		Debug:          debug,
		Sampling:       cfg.Sampling,
		CacheMaxSize:   cfg.CacheMaxFlows,
		EnablePCA:      cfg.EnablePCA,
		UseEbpfManager: cfg.EbpfProgramManagerMode,
		FilterConfig:   filterRules,
	}

	fetcher, err := tracer.NewPacketFetcher(ebpfConfig)
	if err != nil {
		return nil, err
	}

	return packetsAgent(cfg, fetcher, packetexportFunc, agentIP)
}

// packetssAgent is a private constructor with injectable dependencies, usable for tests
func packetsAgent(
	cfg *config.Agent,
	fetcher ebpfPacketFetcher,
	packetexporter node.TerminalFunc[[]*model.PacketRecord],
	agentIP net.IP,
) (*Packets, error) {
	perfTracer := flow.NewPerfTracer(fetcher, cfg.CacheActiveTimeout)
	packetbuffer := flow.NewPerfBuffer(cfg.CacheMaxFlows, cfg.CacheActiveTimeout)
	informer := createInformer(cfg, metrics.NoOp())

	return &Packets{
		ebpf:         fetcher,
		cfg:          cfg,
		packetbuffer: packetbuffer,
		perfTracer:   perfTracer,
		informer:     informer,
		agentIP:      agentIP,
		exporter:     packetexporter,
	}, nil
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

func buildPacketExporter(cfg *config.Agent) (node.TerminalFunc[[]*model.PacketRecord], error) {
	switch cfg.Export {
	case "grpc":
		return buildGRPCPacketExporter(cfg)
	case "direct-flp":
		return buildPacketDirectFLPExporter(cfg)
	default:
		return nil, fmt.Errorf("unsupported packet export type %s", cfg.Export)
	}
}

func buildPacketDirectFLPExporter(cfg *config.Agent) (node.TerminalFunc[[]*model.PacketRecord], error) {
	flpExporter, err := exporter.StartDirectFLP(cfg.FLPConfig, cfg.BuffersLength)
	if err != nil {
		return nil, err
	}
	return flpExporter.ExportPackets, nil
}

// Run a Packets agent. The function will keep running in the same thread
// until the passed context is canceled
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
	plog.Debug("connecting packets' processing graph")

	perfTracer := node.AsStart(p.perfTracer.TraceLoop(ctx))

	ebl := p.cfg.ExporterBufferLength
	if ebl == 0 {
		ebl = p.cfg.BuffersLength
	}

	packetbuffer := node.AsMiddle(p.packetbuffer.PBuffer, node.ChannelBufferLen(p.cfg.BuffersLength))

	perfTracer.SendsTo(packetbuffer)

	export := node.AsTerminal(p.exporter, node.ChannelBufferLen(ebl))

	packetbuffer.SendsTo(export)
	perfTracer.Start()

	return export, nil
}
