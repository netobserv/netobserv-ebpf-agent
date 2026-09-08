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
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	tracerpackets "github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/packets"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/plaintext"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/sirupsen/logrus"
)

var plog = logrus.WithField("component", "agent.Packets")

// Packets reporting agent
type Agent struct {
	cfg *config.Agent

	informer ifaces.Informer
	ebpf     ebpfPacketFetcher

	// processing nodes to be wired in the buildAndStartPipeline method
	ringbufTracer     *RingbufTracer
	packetbuffer      *Buffer
	plaintextTracer   *flow.PlaintextTracer
	plaintextBuffer   *flow.PlaintextBuffer
	plaintextExporter node.TerminalFunc[[]*model.PlaintextRecord]
	plaintextScope    *plaintext.Scope
	exporter          node.TerminalFunc[[]*model.PacketRecord]

	agentIP net.IP

	status common.Status
}

type ebpfPacketFetcher interface {
	io.Closer
	common.TCAttacher
	LookupAndDeleteMap(*metrics.Metrics) map[int][]*byte
	ReadPerf() (ringbuf.Record, error)
	ReadSSLRingBuf() (ringbuf.Record, error)
}

// New instantiates a new packet capture agent from configuration.
func New(cfg *config.Agent) (*Agent, error) {
	plog.Info("initializing Packets agent")
	config.ManageDeprecatedConfigs(cfg)

	plog.Info("[PCA]acquiring Agent IP")
	agentIP, err := common.FetchAgentIP(cfg)
	if err != nil {
		return nil, fmt.Errorf("acquiring Agent IP: %w", err)
	}

	packetexportFunc, plaintextExportFunc, err := buildPacketExporters(cfg)
	if err != nil {
		return nil, err
	}

	ingress, egress := common.FlowDirections(cfg)
	debug := cfg.LogLevel == logrus.TraceLevel.String() || cfg.LogLevel == logrus.DebugLevel.String()
	filterRules, err := common.ParseFlowFilterRules(cfg.FlowFilterRules)
	if err != nil {
		return nil, err
	}
	var scope *plaintext.Scope
	if cfg.EnableOpenSSLTracking {
		scope = plaintext.NewScope(
			filterRules,
			cfg.Packets.TLSPlaintextPIDAllowlist,
			cfg.Packets.TLSPlaintextDedupEnabled,
			cfg.Packets.TLSPlaintextDedupWindow,
			cfg.Packets.TLSPlaintextMinBytes,
		)
		scope.Start()
	}

	ebpfConfig := &tracerpackets.FetcherConfig{
		Agent:          *cfg,
		EnableIngress:  ingress,
		EnableEgress:   egress,
		Debug:          debug,
		FilterConfig:   filterRules,
		PlaintextScope: scope,
	}

	fetcher, err := tracerpackets.NewFetcher(ebpfConfig)
	if err != nil {
		return nil, err
	}

	return newAgent(cfg, fetcher, packetexportFunc, plaintextExportFunc, agentIP, scope)
}

// newAgent is a private constructor with injectable dependencies, usable for tests.
func newAgent(
	cfg *config.Agent,
	fetcher ebpfPacketFetcher,
	packetexporter node.TerminalFunc[[]*model.PacketRecord],
	plaintextExporter node.TerminalFunc[[]*model.PlaintextRecord],
	agentIP net.IP,
	scope *plaintext.Scope,
) (*Agent, error) {
	ringbufTracer := NewRingbufTracer(fetcher, cfg.CacheActiveTimeout)
	packetbuffer := NewBuffer(cfg.CacheMaxFlows, cfg.CacheActiveTimeout)
	informer := common.CreateInformer(cfg, metrics.NoOp())

	a := &Agent{
		ebpf:              fetcher,
		cfg:               cfg,
		packetbuffer:      packetbuffer,
		ringbufTracer:     ringbufTracer,
		informer:          informer,
		agentIP:           agentIP,
		exporter:          packetexporter,
		plaintextExporter: plaintextExporter,
	}

	if cfg.EnableOpenSSLTracking && plaintextExporter == nil {
		return nil, fmt.Errorf("TLS plaintext capture requires export=direct-flp")
	}

	if cfg.EnableOpenSSLTracking {
		a.plaintextTracer = flow.NewPlaintextTracer(fetcher, metrics.NoOp(), scope)
		a.plaintextBuffer = flow.NewPlaintextBuffer(cfg.CacheMaxFlows, cfg.CacheActiveTimeout)
		a.plaintextScope = scope
	}

	return a, nil
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
		flpExporter, err := exporterpackets.StartDirectFLP(cfg.FLPConfig, cfg.BuffersLength, cfg.Packets.TLSPlaintextPreviewBytes)
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
	pcapStreamer, err := exporterpackets.StartGRPCPacketSend(cfg.TargetHost, cfg.TargetPort)
	if err != nil {
		return nil, err
	}
	return pcapStreamer.ExportGRPCPackets, nil
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
	if a.plaintextScope != nil {
		a.plaintextScope.Close()
	}
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

	if a.plaintextTracer != nil && a.plaintextExporter != nil {
		ptTracer := node.AsStart(a.plaintextTracer.TraceLoop(ctx))
		ptBuffer := node.AsMiddle(a.plaintextBuffer.PBuffer, node.ChannelBufferLen(a.cfg.BuffersLength))
		ptExport := node.AsTerminal(a.plaintextExporter, node.ChannelBufferLen(ebl))
		ptTracer.SendsTo(ptBuffer)
		ptBuffer.SendsTo(ptExport)
		ptTracer.Start()
	}

	return export, nil
}
