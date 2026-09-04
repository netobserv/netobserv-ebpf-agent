package packets

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/netobserv/gopipes/pkg/node"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/agent/common"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	exporterpackets "github.com/netobserv/netobserv-ebpf-agent/pkg/exporter/packets"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	tracerpackets "github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/packets"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/sirupsen/logrus"
)

var plog = logrus.WithField("component", "agent.Packets")

// Packets reporting agent
type Agent struct {
	cfg *config.Agent

	// input data providers
	informer ifaces.Informer
	ebpf     ebpfPacketFetcher

	// processing nodes to be wired in the buildAndStartPipeline method
	ringbufTracer *RingbufTracer
	packetbuffer  *Buffer
	exporter      node.TerminalFunc[[]*model.PacketRecord]

	// elements used to decorate flows with extra information
	agentIP net.IP

	status common.Status
}

type ebpfPacketFetcher interface {
	io.Closer
	common.TCAttacher
	LookupAndDeleteMap(*metrics.Metrics) map[int][]*byte
	ReadPerf() (ringbuf.Record, error)
}

// New instantiates a new packet capture agent from configuration.
func New(cfg *config.Agent) (*Agent, error) {
	plog.Info("initializing Packets agent")

	// manage deprecated configs
	config.ManageDeprecatedConfigs(cfg)

	plog.Info("[PCA]acquiring Agent IP")
	agentIP, err := common.FetchAgentIP(cfg)
	if err != nil {
		return nil, fmt.Errorf("acquiring Agent IP: %w", err)
	}

	// configure selected exporter
	packetexportFunc, err := buildPacketExporter(cfg)
	if err != nil {
		return nil, err
	}

	ingress, egress := common.FlowDirections(cfg)
	debug := cfg.LogLevel == logrus.TraceLevel.String() || cfg.LogLevel == logrus.DebugLevel.String()
	filterRules, err := common.ParseFlowFilterRules(cfg.FlowFilterRules)
	if err != nil {
		return nil, err
	}
	ebpfConfig := &tracerpackets.FetcherConfig{
		Agent:         *cfg,
		EnableIngress: ingress,
		EnableEgress:  egress,
		Debug:         debug,
		FilterConfig:  filterRules,
	}

	fetcher, err := tracerpackets.NewFetcher(ebpfConfig)
	if err != nil {
		return nil, err
	}

	return newAgent(cfg, fetcher, packetexportFunc, agentIP)
}

// newAgent is a private constructor with injectable dependencies, usable for tests.
func newAgent(
	cfg *config.Agent,
	fetcher ebpfPacketFetcher,
	packetexporter node.TerminalFunc[[]*model.PacketRecord],
	agentIP net.IP,
) (*Agent, error) {
	ringbufTracer := NewRingbufTracer(fetcher, cfg.CacheActiveTimeout)
	packetbuffer := NewBuffer(cfg.CacheMaxFlows, cfg.CacheActiveTimeout)
	informer := common.CreateInformer(cfg, metrics.NoOp())

	return &Agent{
		ebpf:          fetcher,
		cfg:           cfg,
		packetbuffer:  packetbuffer,
		ringbufTracer: ringbufTracer,
		informer:      informer,
		agentIP:       agentIP,
		exporter:      packetexporter,
	}, nil
}

func buildGRPCPacketExporter(cfg *config.Agent) (node.TerminalFunc[[]*model.PacketRecord], error) {
	if cfg.TargetHost == "" || cfg.TargetPort == 0 {
		return nil, fmt.Errorf("missing target host or port for PCA: %s:%d",
			cfg.TargetHost, cfg.TargetPort)
	}
	plog.Info("starting gRPC Packet send")
	pcapStreamer, err := exporterpackets.StartGRPCPacketSend(cfg.TargetHost, cfg.TargetPort)
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
	flpExporter, err := exporterpackets.StartDirectFLP(cfg.FLPConfig, cfg.BuffersLength)
	if err != nil {
		return nil, err
	}
	return flpExporter.ExportPackets, nil
}

// Run a Packets agent. The function will keep running in the same thread
// until the passed context is canceled
func (a *Agent) Run(ctx context.Context) error {
	a.status = common.StatusStarting
	plog.Info("Starting Packets agent")
	graph, err := a.buildAndStartPipeline(ctx)
	if err != nil {
		return fmt.Errorf("error starting processing graph: %w", err)
	}

	a.status = common.StatusStarted
	plog.Info("Packets agent successfully started")
	<-ctx.Done()

	a.status = common.StatusStopping
	plog.Info("stopping Packets agent")
	if err := a.ebpf.Close(); err != nil {
		plog.WithError(err).Warn("eBPF resources not correctly closed")
	}

	plog.Debug("waiting for all nodes to finish their pending work")
	<-graph.Done()

	a.status = common.StatusStopped
	plog.Info("Packets agent stopped")
	return nil
}

func (a *Agent) Status() common.Status {
	return a.status
}

func (a *Agent) buildAndStartPipeline(ctx context.Context) (*node.Terminal[[]*model.PacketRecord], error) {
	if !a.cfg.EbpfProgramManagerMode {
		plog.Debug("registering interfaces' listener in background")
		err := common.StartInterfaceListener(ctx, a.ebpf, a.cfg, metrics.NoOp(), a.informer)
		if err != nil {
			return nil, err
		}
	}
	plog.Debug("connecting packets' processing graph")

	ringbufTracer := node.AsStart(a.ringbufTracer.TraceLoop(ctx))

	ebl := a.cfg.ExporterBufferLength
	if ebl == 0 {
		ebl = a.cfg.BuffersLength
	}

	packetbuffer := node.AsMiddle(a.packetbuffer.PBuffer, node.ChannelBufferLen(a.cfg.BuffersLength))

	ringbufTracer.SendsTo(packetbuffer)

	export := node.AsTerminal(a.exporter, node.ChannelBufferLen(ebl))

	packetbuffer.SendsTo(export)
	ringbufTracer.Start()

	return export, nil
}
