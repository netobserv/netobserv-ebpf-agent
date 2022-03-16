package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/netobserv/gopipes/pkg/node"
	"github.com/netobserv/netobserv-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-agent/pkg/flow"
	"github.com/sirupsen/logrus"
)

var alog = logrus.WithField("component", "agent.Flows")

// Flows reporting agent
type Flows struct {
	tracers   map[string]flowTracer
	accounter flowAccounter
	exporter  flowExporter
}

type flowTracer interface {
	Trace(ctx context.Context, forwardFlows chan<- *flow.Record)
	Register() error
	Unregister() error
}

type flowAccounter interface {
	Account(in <-chan *flow.Record, out chan<- *flow.Record)
}

type flowExporter func(in <-chan *flow.Record)

// FlowsAgent instantiates a new agent, given a configuration.
func FlowsAgent(cfg Config) (*Flows, error) {
	alog.Info("initializing Flows agent")
	interfaces, err := getInterfaces(&cfg)
	if err != nil {
		return nil, err
	}
	tracers := map[string]flowTracer{}
	for iface := range interfaces {
		tracers[iface] = ebpf.NewFlowTracer(iface)
	}
	return &Flows{
		tracers:   tracers,
		accounter: flow.NewAccounter(cfg.CacheMaxFlows, cfg.BuffersLen, cfg.CacheActiveTimeout),
		// For now, just print flows. TODO: NETOBSERV-202
		exporter: func(in <-chan *flow.Record) {
			for record := range in {
				str, err := json.Marshal(record)
				if err != nil {
					logrus.WithError(err).WithField("record", record).Warn("can't unmarshal record")
				}
				fmt.Println(string(str))
			}
		},
	}, nil
}

// Run a Flows agent. The function will keep running in the same thread
// until the passed context is canceled
func (f *Flows) Run(ctx context.Context) error {
	alog.Info("starting Flows agent")
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
	alog.Debug("registering accounter")
	accounter := node.AsMiddle(f.accounter.Account)
	alog.Debug("registering exporter")
	exporter := node.AsTerminal(f.exporter)

	alog.Debug("connecting graph")
	for _, t := range tracers {
		t.SendsTo(accounter)
	}
	accounter.SendsTo(exporter)

	alog.Debug("starting graph")
	for _, t := range tracers {
		t.Start()
	}

	alog.Info("Flows agent successfully started")
	<-ctx.Done()
	alog.Info("stopping Flows agent")

	alog.Debug("waiting for all nodes to finish their pending work")
	<-exporter.Done()

	alog.Info("Flows agent stopped")
	return nil
}
