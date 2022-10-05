package agent

import (
	"context"
	"errors"
	"fmt"
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
	exporter   flowExporter
	interfaces ifaces.Informer
	filter     interfaceFilter
	tracer     flowTracer
	cfg        *Config
}

// flowTracer abstracts the interface of ebpf.FlowTracer to allow dependency injection in tests
type flowTracer interface {
	Trace(ctx context.Context, forwardFlows chan<- []*flow.Record)
	Register(iface ifaces.Interface) error
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
	registerer := ifaces.NewRegisterer(informer, cfg.BuffersLength)

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
		transport := kafkago.Transport{}
		if cfg.KafkaEnableTLS {
			tlsConfig, err := buildTLSConfig(cfg)
			if err != nil {
				return nil, err
			}
			transport.TLS = tlsConfig
		}
		exportFunc = (&exporter.KafkaProto{
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
				Balancer:     &kafkago.RoundRobin{},
			},
		}).ExportFlows
	default:
		return nil, fmt.Errorf("wrong export type %s. Admitted values are grpc, kafka", cfg.Export)
	}

	interfaceNamer := func(ifIndex int) string {
		iface, ok := registerer.IfaceNameForIndex(ifIndex)
		if !ok {
			return "unknown"
		}
		return iface
	}

	ingress, egress := flowDirections(cfg)

	tracer, err := ebpf.NewFlowTracer(
		cfg.Sampling, cfg.CacheMaxFlows, cfg.BuffersLength, cfg.CacheActiveTimeout,
		ingress, egress,
		interfaceNamer,
	)
	if err != nil {
		return nil, err
	}

	return &Flows{
		tracer:     tracer,
		exporter:   exportFunc,
		interfaces: informer,
		filter:     filter,
		cfg:        cfg,
	}, nil
}

func flowDirections(cfg *Config) (ingress, egress bool) {
	switch cfg.Direction {
	case DirectionIngress:
		return true, false
	case DirectionEgress:
		return false, true
	case DirectionBoth:
		return true, true
	default:
		alog.Warnf("unknown DIRECTION %q. Tracing both ingress and egress traffic", cfg.Direction)
		return true, true
	}
}

// Run a Flows agent. The function will keep running in the same thread
// until the passed context is canceled
func (f *Flows) Run(ctx context.Context) error {
	alog.Info("starting Flows agent")
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

	tctx, cancelTracer := context.WithCancel(ctx)
	go f.tracer.Trace(tctx, tracedRecords)

	go func() {
		for {
			select {
			case <-ctx.Done():
				slog.Debug("canceling flow tracer")
				cancelTracer()
				slog.Debug("closing channel and exiting internal goroutine")
				close(tracedRecords)
				return
			case event := <-ifaceEvents:
				slog.WithField("event", event).Debug("received event")
				switch event.Type {
				case ifaces.EventAdded:
					f.onInterfaceAdded(event.Interface)
				case ifaces.EventDeleted:
					// qdiscs, ingress and egress filters are automatically deleted so we don't need to
					// specifically detach them from the tracer
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
	if f.cfg.Deduper == DeduperFirstCome {
		deduper := node.AsMiddle(flow.Dedupe(f.cfg.DeduperFCExpiry))
		tracersCollector.SendsTo(deduper)
		deduper.SendsTo(export)
	} else {
		tracersCollector.SendsTo(export)
	}
	alog.Debug("starting graph")
	tracersCollector.Start()
	return export
}

func (f *Flows) onInterfaceAdded(iface ifaces.Interface) {
	// ignore interfaces that do not match the user configuration acceptance/exclusion lists
	if !f.filter.Allowed(iface.Name) {
		alog.WithField("interface", iface).
			Debug("interface does not match the allow/exclusion filters. Ignoring")
		return
	}
	alog.WithField("interface", iface).Info("interface detected. Registering flow tracer")
	if err := f.tracer.Register(iface); err != nil {
		alog.WithField("interface", iface).WithError(err).
			Warn("can't register flow tracer. Ignoring")
		return
	}
}
