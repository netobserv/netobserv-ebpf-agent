package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/netobserv/gopipes/pkg/node"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/exporter"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	kafkago "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/compress"
	"github.com/sirupsen/logrus"
)

var alog = logrus.WithField("component", "agent.Flows")

// Flows reporting agent
type Flows struct {
	// trMutex provides synchronized access to the tracers map
	trMutex sync.Mutex
	// tracers stores a flowTracer implementation for each interface in the system, with a
	// cancel function that allows stopping it when its interface is deleted
	tracers    map[ifaces.Name]cancellableTracer
	exporter   flowExporter
	interfaces ifaces.Informer
	filter     interfaceFilter
	// tracerFactory specifies how to instantiate flowTracer implementations
	tracerFactory func(string) flowTracer
	tracerCloser  io.Closer
	cfg           *Config
}

// flowTracer abstracts the interface of ebpf.FlowTracer to allow dependency injection in tests
type flowTracer interface {
	Trace(ctx context.Context, forwardFlows chan<- []*flow.Record)
	Register() error
	Unregister() error
}

type cancellableTracer struct {
	tracer flowTracer
	cancel context.CancelFunc
}

// flowExporter abstract the ExportFlows' method of exporter.GRPCProto to allow dependency injection
// in tests
type flowExporter func(in <-chan []*flow.Record)

// FlowsAgent instantiates a new agent, given a configuration.
func FlowsAgent(cfg *Config) (*Flows, error) {
	alog.Info("initializing Flows agent")

	// configure allow/deny interfaces filter
	filter, err := initInterfaceFilter(cfg.Interfaces, cfg.ExcludeInterfaces)
	if err != nil {
		return nil, fmt.Errorf("configuring interface filters: %w", err)
	}

	// configure informer for new interfaces
	var informer ifaces.Informer
	switch cfg.ListenInterfaces {
	case ListenPoll:
		alog.WithField("period", cfg.ListenPollPeriod).
			Debug("listening for new interfaces: use polling")
		informer = ifaces.NewPoller(cfg.ListenPollPeriod, cfg.BuffersLength)
	case ListenWatch:
		alog.Debug("listening for new interfaces: use watching")
		informer = ifaces.NewWatcher(cfg.BuffersLength)
	default:
		alog.WithField("providedValue", cfg.ListenInterfaces).
			Warn("wrong interface listen method. Using file watcher as default")
		informer = ifaces.NewWatcher(cfg.BuffersLength)
	}

	// configure selected exporter
	var exportFunc flowExporter
	switch cfg.Export {
	case "grpc":
		if cfg.TargetHost == "" || cfg.TargetPort == 0 {
			return nil, fmt.Errorf("missing target host or port: %s:%d",
				cfg.TargetHost, cfg.TargetPort)
		}
		target := fmt.Sprintf("%s:%d", cfg.TargetHost, cfg.TargetPort)
		grpcExporter, err := exporter.StartGRPCProto(target)
		if err != nil {
			return nil, err
		}
		exportFunc = grpcExporter.ExportFlows
	case "kafka":
		if len(cfg.KafkaBrokers) == 0 {
			return nil, errors.New("at least one Kafka broker is needed")
		}
		var compression compress.Compression
		if err := compression.UnmarshalText([]byte(cfg.KafkaCompression)); err != nil {
			return nil, fmt.Errorf("wrong Kafka compression value %s. Admitted values are "+
				"none, gzip, snappy, lz4, zstd: %w", cfg.KafkaCompression, err)
		}
		exportFunc = (&exporter.KafkaJSON{
			Writer: &kafkago.Writer{
				Addr:      kafkago.TCP(cfg.KafkaBrokers...),
				Topic:     cfg.KafkaTopic,
				BatchSize: cfg.KafkaBatchSize,
				// Segmentio's Kafka-go does not behave as standard Kafka library, and would
				// throttle any Write invocation until reaching the timeout.
				// Since we invoke write once each CacheActiveTimeout, we can safely disable this
				// timeout throttling
				// https://github.com/netobserv/flowlogs-pipeline/pull/233#discussion_r897830057
				BatchTimeout: time.Nanosecond,
				BatchBytes:   int64(cfg.KafkaBatchBytes),
				Async:        cfg.KafkaAsync,
				Compression:  compression,
			},
		}).ExportFlows
	default:
		return nil, fmt.Errorf("wrong export type %s. Admitted values are grpc, kafka", cfg.Export)
	}

	factory, factoryCloser, err := ebpf.NewFlowTracerFactory(
		cfg.Sampling, cfg.CacheMaxFlows, cfg.BuffersLength, cfg.CacheActiveTimeout)
	if err != nil {
		return nil, err
	}

	return &Flows{
		tracers:    map[ifaces.Name]cancellableTracer{},
		exporter:   exportFunc,
		interfaces: informer,
		filter:     filter,
		tracerFactory: func(iface string) flowTracer {
			return factory(iface)
		},
		tracerCloser: factoryCloser,
		cfg:          cfg,
	}, nil
}

// Run a Flows agent. The function will keep running in the same thread
// until the passed context is canceled
func (f *Flows) Run(ctx context.Context) error {
	alog.Info("starting Flows agent")

	systemSetup()

	tracedRecords, err := f.interfacesManager(ctx)
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

// interfacesManager uses an informer to check new/deleted network interfaces. For each running
// interface, it registers a flow tracer that will forward new flows to the returned channel
func (f *Flows) interfacesManager(ctx context.Context) (<-chan []*flow.Record, error) {
	slog := alog.WithField("function", "interfacesManager")

	slog.Debug("subscribing for network interface events")
	ifaceEvents, err := f.interfaces.Subscribe(ctx)
	if err != nil {
		return nil, fmt.Errorf("instantiating interfaces' informer: %w", err)
	}

	tracedRecords := make(chan []*flow.Record, f.cfg.BuffersLength)
	go func() {
		for {
			select {
			case <-ctx.Done():
				slog.Debug("detaching all the flow tracers before closing the records' channel")
				f.detachAllTracers()
				slog.Debug("closing channel and exiting internal goroutine")
				close(tracedRecords)
				if f.tracerCloser != nil {
					if err := f.tracerCloser.Close(); err != nil {
						slog.WithError(err).Warn("couldn't close Flows' Tracer Factory")
					}
				}
				return
			case event := <-ifaceEvents:
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

// processRecords creates the tracers --> accounter --> forwarder Flow processing graph
func (f *Flows) processRecords(tracedRecords <-chan []*flow.Record) *node.Terminal {
	// The start node receives Records from the eBPF flow tracers. Currently it is just an external
	// channel forwarder, as the Pipes library does not yet accept
	// adding/removing nodes dynamically: https://github.com/mariomac/pipes/issues/5
	alog.Debug("registering tracers' input")
	tracersCollector := node.AsInit(func(out chan<- []*flow.Record) {
		for i := range tracedRecords {
			out <- i
		}
	})
	alog.Debug("registering exporter")
	export := node.AsTerminal(f.exporter)
	alog.Debug("connecting graph")
	tracersCollector.SendsTo(export)
	alog.Debug("starting graph")
	tracersCollector.Start()
	return export
}

func (f *Flows) onInterfaceAdded(ctx context.Context, name ifaces.Name, flowsCh chan []*flow.Record) {
	// ignore interfaces that do not match the user configuration acceptance/exclusion lists
	if !f.filter.Allowed(name) {
		alog.WithField("name", name).
			Debug("interface does not match the allow/exclusion filters. Ignoring")
		return
	}
	f.trMutex.Lock()
	defer f.trMutex.Unlock()
	if _, ok := f.tracers[name]; !ok {
		alog.WithField("name", name).Info("interface detected. Registering flow tracer")
		tracer := f.tracerFactory(string(name))
		if err := tracer.Register(); err != nil {
			alog.WithField("interface", name).WithError(err).
				Warn("can't register flow tracer. Ignoring")
			return
		}
		tctx, cancel := context.WithCancel(ctx)
		go tracer.Trace(tctx, flowsCh)
		f.tracers[name] = cancellableTracer{
			tracer: tracer,
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
		delete(f.tracers, name)
		// qdiscs, ingress and egress filters are automatically deleted so we don't need to
		// specifically detach the tracer
	}
}

func (f *Flows) detachAllTracers() {
	f.trMutex.Lock()
	defer f.trMutex.Unlock()
	for name, ft := range f.tracers {
		ft.cancel()
		flog := alog.WithField("name", name)
		flog.Info("unregistering flow tracer")
		if err := ft.tracer.Unregister(); err != nil {
			flog.WithError(err).Warn("can't unregister flow tracer")
		}
	}
	f.tracers = map[ifaces.Name]cancellableTracer{}
}
