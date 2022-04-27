package agent

import (
	"context"
	"fmt"
	"sync"

	"github.com/netobserv/gopipes/pkg/node"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/exporter"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	"github.com/sirupsen/logrus"
)

var alog = logrus.WithField("component", "agent.Flows")

// Flows reporting agent
type Flows struct {
	trMutex        sync.Mutex
	tracers        map[ifaces.Name]flowTracer
	accounter      flowAccounter
	exporter       flowExporter
	interfaceNames ifaces.NamesProvider
	bufLen         int
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
		tracers: map[ifaces.Name]flowTracer{},
		accounter: flow.NewAccounter(cfg.CacheMaxFlows,
			cfg.BuffersLength,
			cfg.CacheActiveTimeout),
		exporter:       grpcExporter.ExportFlows,
		interfaceNames: namesProvider,
		bufLen:         cfg.BuffersLength,
	}, nil
}

// Run a Flows agent. The function will keep running in the same thread
// until the passed context is canceled
func (f *Flows) Run(ctx context.Context) error {
	alog.Info("starting Flows agent")

	graph := f.processRecords(tracedRecords)
	f.subscribeForRecords(tracedRecords)

	alog.Debug("registering flow tracers")
	var tracers []*node.Init
	for i, t := range f.tracers {
		// make sure the background/deferred functions use this loop's values
		iface, tracer := i, t
		tlog := alog.WithField("iface", iface)
		tlog.Debug("registering flow tracer")
		if err := tracer.Register(); err != nil {
			return err
		}
		defer func() {
			tlog.Debug("unregistering flow tracer")
			if err := tracer.Unregister(); err != nil {
				tlog.WithError(err).Warn("error unregistering flow tracer")
			}
		}()
		tracers = append(tracers,
			node.AsInit(func(out chan<- *flow.Record) {
				tracer.Trace(ctx, out)
				tlog.Debug("tracer routine ended")
			}))
	}

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
	deviceEvents, err := ifaces.Informer(ctx, f.interfaceNames, f.bufLen)
	if err != nil {
		return nil, err
	}
	tracedRecords := make(chan *flow.Record, f.bufLen)

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
					f.onInterfaceAdded(event.Interface)
				}

			}
		}
	}()

	return tracedRecords, nil
}

func (f *Flows) onInterfaceAdded(name ifaces.Name) {
	// first: filter the interface name according to the configuration

	f.trMutex.Lock()
	defer f.trMutex.Unlock()
	if ft, ok := f.tracers[name]; !ok {
	}
}
