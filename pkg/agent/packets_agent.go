package agent

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/cilium/ebpf/perf"
	"github.com/netobserv/gopipes/pkg/node"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/exporter"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
)

// Packets reporting agent
type Packets struct {
	cfg *Config

	// input data providers
	interfaces ifaces.Informer
	filter     interfaceFilter
	ebpf       ebpfPacketFetcher

	// processing nodes to be wired in the buildAndStartPipeline method
	perfTracer   *flow.PerfTracer
	packetbuffer *flow.PerfBuffer
	exporter     node.TerminalFunc[[]*flow.PacketRecord]

	// elements used to decorate flows with extra information
	interfaceNamer flow.InterfaceNamer
	agentIP        net.IP

	status Status
}

type ebpfPacketFetcher interface {
	io.Closer
	Register(iface ifaces.Interface) error

	LookupAndDeleteMap() map[int][]*byte
	ReadPerf() (perf.Record, error)
}

// PacketsAgent instantiates a new agent, given a configuration.
func PacketsAgent(cfg *Config) (*Packets, error) {
	plog.Info("initializing Packets agent")

	// configure informer for new interfaces
	informer := configureInformer(cfg, plog)

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

	fetcher, err := ebpf.NewPacketFetcher(cfg.CacheMaxFlows, cfg.PCAFilters, ingress, egress)
	if err != nil {
		return nil, err
	}

	return packetsAgent(cfg, informer, fetcher, packetexportFunc, agentIP)
}

// packetssAgent is a private constructor with injectable dependencies, usable for tests
func packetsAgent(cfg *Config,
	informer ifaces.Informer,
	fetcher ebpfPacketFetcher,
	packetexporter node.TerminalFunc[[]*flow.PacketRecord],
	agentIP net.IP,
) (*Packets, error) {
	// configure allow/deny interfaces filter
	filter, err := initInterfaceFilter(cfg.Interfaces, cfg.ExcludeInterfaces)
	if err != nil {
		return nil, fmt.Errorf("configuring interface filters: %w", err)
	}

	registerer := ifaces.NewRegisterer(informer, cfg.BuffersLength)

	interfaceNamer := func(ifIndex int) string {
		iface, ok := registerer.IfaceNameForIndex(ifIndex)
		if !ok {
			return "unknown"
		}
		return iface
	}

	perfTracer := flow.NewPerfTracer(fetcher, cfg.CacheActiveTimeout)

	packetbuffer := flow.NewPerfBuffer(cfg.CacheMaxFlows, cfg.CacheActiveTimeout)

	return &Packets{
		ebpf:           fetcher,
		interfaces:     registerer,
		filter:         filter,
		cfg:            cfg,
		packetbuffer:   packetbuffer,
		perfTracer:     perfTracer,
		agentIP:        agentIP,
		interfaceNamer: interfaceNamer,
		exporter:       packetexporter,
	}, nil
}

func buildPacketExporter(cfg *Config) (node.TerminalFunc[[]*flow.PacketRecord], error) {
	if cfg.PCAServerPort == 0 {
		return nil, fmt.Errorf("missing PCA Server port: %d",
			cfg.PCAServerPort)
	}
	pcapStreamer, err := exporter.StartPCAPSend(fmt.Sprintf("%d", cfg.PCAServerPort))
	if err != nil {
		return nil, err
	}

	return pcapStreamer.ExportFlows, err

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

func (p *Packets) interfacesManager(ctx context.Context) error {
	slog := plog.WithField("function", "interfacesManager")

	slog.Debug("subscribing for network interface events")
	ifaceEvents, err := p.interfaces.Subscribe(ctx)
	if err != nil {
		return fmt.Errorf("instantiating interfaces' informer: %w", err)
	}

	go interfaceListener(ctx, ifaceEvents, slog, p.onInterfaceAdded)

	return nil
}

func (p *Packets) buildAndStartPipeline(ctx context.Context) (*node.Terminal[[]*flow.PacketRecord], error) {

	plog.Debug("registering interfaces' listener in background")
	err := p.interfacesManager(ctx)
	if err != nil {
		return nil, err
	}

	plog.Debug("connecting packets' processing graph")

	perfTracer := node.AsStart(p.perfTracer.TraceLoop(ctx))

	ebl := p.cfg.ExporterBufferLength
	if ebl == 0 {
		ebl = p.cfg.BuffersLength
	}

	packetbuffer := node.AsMiddle(p.packetbuffer.PBuffer,
		node.ChannelBufferLen(p.cfg.BuffersLength))

	perfTracer.SendsTo(packetbuffer)

	export := node.AsTerminal(p.exporter,
		node.ChannelBufferLen(ebl))

	packetbuffer.SendsTo(export)
	perfTracer.Start()

	return export, nil
}

func (p *Packets) onInterfaceAdded(iface ifaces.Interface) {
	// ignore interfaces that do not match the user configuration acceptance/exclusion lists
	if !p.filter.Allowed(iface.Name) {
		plog.WithField("interface", iface).
			Debug("[PCA]interface does not match the allow/exclusion filters. Ignoring")
		return
	}
	plog.WithField("[PCA]interface", iface).Info("interface detected. Registering packets ebpfFetcher")
	if err := p.ebpf.Register(iface); err != nil {
		plog.WithField("[PCA]interface", iface).WithError(err).
			Warn("can't register packet ebpfFetcher. Ignoring")
		return
	}
}
