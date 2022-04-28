package agent

import (
	"context"
	"fmt"
	"sync"

	"github.com/netobserv/gopipes/pkg/node"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/exporter"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	"github.com/sirupsen/logrus"
)

var alog = logrus.WithField("component", "agent.Flows")

// Flows reporting agent
type Flows struct {
	trMutex        sync.Mutex
	tracers        map[ifaces.Name]cancellableTracer
	accounter      flowAccounter
	exporter       flowExporter
	interfaceNames ifaces.NamesProvider
	filter         interfaceFilter
	tracerFactory  func(name string, sampling uint32) flowTracer
	cfg            *Config
}

type cancellableTracer struct {
	tracer flowTracer
	cancel context.CancelFunc
}

type flowTracer interface {
	Trace(ctx context.Context, forwardFlows chan<- *flow.Record)
	Register() error
	Unregister() error
}

type flowAccounter interface {
	Account(in <-chan *flow.Record, out chan<- []*flow.Record)
}

type flowExporter func(in <-chan []*flow.Record)

// FlowsAgent instantiates a new agent, given a configuration.
func FlowsAgent(cfg *Config) (*Flows, error) {
	alog.Info("initializing Flows agent")

	filter, err := initInterfaceFilter(cfg.Interfaces, cfg.ExcludeInterfaces)
	if err != nil {
		return nil, fmt.Errorf("configuring interface filters: %w", err)
	}

	var namesProvider ifaces.NamesProvider
	switch cfg.ListenDevices {
	case ListenPoll:
		alog.WithField("period", cfg.ListenPollPeriod).
			Debug("listening for new interfaces: use polling")
		namesProvider = ifaces.NewPoller(cfg.ListenPollPeriod)
	case ListenWatch:
		alog.WithField("file", cfg.ListenWatchDevFile).
			Debug("listening for new interfaces: use watching")
		namesProvider = ifaces.NewWatcher(cfg.ListenWatchDevFile, cfg.BuffersLength)
	default:
		alog.WithFields(logrus.Fields{
			"providedValue": cfg.ListenDevices,
			"file":          cfg.ListenWatchDevFile,
		}).Warn("wrong device listen method. Using file watcher as default")
		namesProvider = ifaces.NewWatcher(cfg.ListenWatchDevFile, cfg.BuffersLength)
	}

	target := fmt.Sprintf("%s:%d", cfg.TargetHost, cfg.TargetPort)
	grpcExporter, err := exporter.StartGRPCProto(target)
	if err != nil {
		return nil, err
	}
	return &Flows{
		tracers: map[ifaces.Name]cancellableTracer{},
		accounter: flow.NewAccounter(cfg.CacheMaxFlows,
			cfg.BuffersLength,
			cfg.CacheActiveTimeout),
		exporter:       grpcExporter.ExportFlows,
		interfaceNames: namesProvider,
		filter:         filter,
		tracerFactory: func(name string, sampling uint32) flowTracer {
			return ebpf.NewFlowTracer(name, sampling)
		},
		cfg: cfg,
	}, nil
}

// Run a Flows agent. The function will keep running in the same thread
// until the passed context is canceled
func (f *Flows) Run(ctx context.Context) error {
	alog.Info("starting Flows agent")

	tracedRecords, err := f.subscribeForRecords(ctx)
	if err != nil {
		return err
	}
	graph := f.processRecords(tracedRecords)

	alog.Info("Flows agent successfully started")
	<-ctx.Done()
	alog.Info("stopping Flows agent")

	alog.Debug("waiting for all nodes to finish their pending work")
	<-graph.Done()

	alog.Info("Flows agent stopped")
	return nil
}

func (f *Flows) processRecords(tracedRecords <-chan *flow.Record) *node.Terminal {
	alog.Debug("registering tracers' input")
	// The start node is just an external channel forwarder, as the pipes library still
	// does not accept plug-in/removing nodes dynamically: https://github.com/mariomac/pipes/issues/5
	tracersCollector := node.AsInit(func(out chan<- *flow.Record) {
		for i := range tracedRecords {
			out <- i
		}
	})
	alog.Debug("registering accounter")
	accounter := node.AsMiddle(f.accounter.Account)
	alog.Debug("registering exporter")
	export := node.AsTerminal(f.exporter)
	alog.Debug("connecting graph")
	tracersCollector.SendsTo(accounter)
	accounter.SendsTo(export)
	alog.Debug("starting graph")
	tracersCollector.Start()
	return export
}

func (f *Flows) subscribeForRecords(ctx context.Context) (<-chan *flow.Record, error) {
	slog := alog.WithField("function", "subscribeForRecords")
	slog.Debug("starting function")
	deviceEvents, err := ifaces.Informer(ctx, f.interfaceNames, f.cfg.BuffersLength)
	if err != nil {
		return nil, err
	}
	tracedRecords := make(chan *flow.Record, f.cfg.BuffersLength)

	go func() {
		for {
			select {
			case <-ctx.Done():
				slog.Debug("closing channel and exiting internal goroutine")
				close(tracedRecords)
				return
			case event := <-deviceEvents:
				slog.WithField("event", event).Debug("received event")
				switch event.Type {
				case ifaces.EventAdded:
					f.onInterfaceAdded(ctx, event.Interface, tracedRecords)
				case ifaces.EventDeleted:
					f.onInterfaceDeleted(event.Interface)
				default:
					slog.WithField("event", event).Warn("unknown event type")
				}
			}
		}
	}()

	return tracedRecords, nil
}

func (f *Flows) onInterfaceAdded(ctx context.Context, name ifaces.Name, flowsCh chan *flow.Record) {
	// first: filter the interface name according to the configuration
	if !f.filter.Allowed(name) {
		alog.WithField("name", name).
			Debug("interface does not match the allow/exclusion filters. Ignoring")
		return
	}
	f.trMutex.Lock()
	defer f.trMutex.Unlock()
	if _, ok := f.tracers[name]; !ok {
		alog.WithField("name", name).Info("new interface added. Registering flow tracer")
		ft := f.tracerFactory(string(name), f.cfg.Sampling)
		if err := ft.Register(); err != nil {
			alog.WithField("interface", name).WithError(err).
				Warn("can't register flow tracer. Ignoring")
			return
		}
		tctx, cancel := context.WithCancel(ctx)
		go ft.Trace(tctx, flowsCh)
		f.tracers[name] = cancellableTracer{
			tracer: ft,
			cancel: cancel,
		}
	}
}

func (f *Flows) onInterfaceDeleted(name ifaces.Name) {
	f.trMutex.Lock()
	defer f.trMutex.Unlock()
	if ft, ok := f.tracers[name]; ok {
		alog.WithField("name", name).Info("interface deleted. Removing flow tracer")
		ft.cancel()
		if err := ft.tracer.Unregister(); err != nil {
			alog.WithField("name", name).WithError(err).
				Warn("can't unregister flow tracer")
		}
		delete(f.tracers, name)
	}
}
