package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer"
	"github.com/sirupsen/logrus"
)

var ilog = logrus.WithField("component", "agent.Interfaces")

type tcAttacher interface {
	Register(iface *ifaces.Interface) error
	UnRegister(iface *ifaces.Interface) error
	AttachTCX(iface *ifaces.Interface) error
	DetachTCX(iface *ifaces.Interface) error
}

type interfaceListener struct {
	attacher tcAttacher
	cfg      *config.Agent
	metrics  *metrics.Metrics
	filter   ifaces.Filter
}

func createInformer(cfg *config.Agent) ifaces.Informer {
	// configure informer for new interfaces
	var informer ifaces.Informer
	switch cfg.ListenInterfaces {
	case config.ListenPoll:
		ilog.WithField("period", cfg.ListenPollPeriod).Info("listening for new interfaces: use polling")
		informer = ifaces.NewPoller(cfg.ListenPollPeriod, cfg.BuffersLength)
	case config.ListenWatch:
		ilog.Info("listening for new interfaces: use watching")
		informer = ifaces.NewWatcher(cfg.BuffersLength)
	default:
		ilog.WithField("providedValue", cfg.ListenInterfaces).Warn("wrong interface listen method. Using file watcher as default")
		informer = ifaces.NewWatcher(cfg.BuffersLength)
	}

	return informer
}

// startInterfaceListener uses an informer to check new/deleted network interfaces. For each running
// interface, it registers a flow ebpfFetcher that will forward new flows to the returned channel
func startInterfaceListener(ctx context.Context, attacher tcAttacher, cfg *config.Agent, m *metrics.Metrics, informer ifaces.Informer) error {
	filter, err := ifaces.FromConfig(cfg)
	if err != nil {
		return err
	}

	registerer, err := ifaces.NewRegisterer(informer, cfg, m)
	if err != nil {
		return err
	}

	interfaceNamer := func(ifIndex int, mac model.MacAddr) string {
		iface, ok := registerer.IfaceNameForIndexAndMAC(ifIndex, mac)
		if !ok {
			return "unknown"
		}
		return iface
	}
	model.SetInterfaceNamer(interfaceNamer)

	ilog.Debug("subscribing for network interface events")
	ifaceEvents, err := registerer.Subscribe(ctx)
	if err != nil {
		return fmt.Errorf("instantiating interfaces informer: %w", err)
	}

	l := interfaceListener{
		attacher: attacher,
		cfg:      cfg,
		metrics:  m,
		filter:   filter,
	}

	go l.start(ctx, ifaceEvents)

	return nil
}

func (i *interfaceListener) start(ctx context.Context, ifaceEvents <-chan ifaces.Event) {
	var attach, detach func(*ifaces.Interface)
	switch i.cfg.TCAttachMode {
	case "tcx":
		attach = i.attachTCX
		detach = i.detachTCX
	case "tc":
		attach = i.attachTC
		detach = i.detachTC
	default:
		attach = i.attachAny
		detach = i.detachAny
	}
	for {
		select {
		case <-ctx.Done():
			ilog.Debug("stopping interfaces' listener")
			return
		case event := <-ifaceEvents:
			ilog.WithField("event", event).Debug("received event")
			// ignore interfaces that do not match the user configuration acceptance/exclusion lists
			allowed, err := i.filter.Allowed(event.Interface.Name)
			if err != nil {
				ilog.WithField("interface", event.Interface).Errorf("encountered error determining if interface is allowed: %v", err)
				continue
			}
			if !allowed {
				ilog.WithField("interface", event.Interface).Debug("interface does not match the allow/exclusion filters. Ignoring")
				continue
			}
			switch event.Type {
			case ifaces.EventAdded:
				attach(&event.Interface)
			case ifaces.EventDeleted:
				detach(&event.Interface)
			default:
				ilog.WithField("event", event).Warn("unknown event type")
			}
		}
	}
}

func runWithRetries(iface *ifaces.Interface, retries int, f func(*ifaces.Interface) error) (int, error) {
	if retries > 1 {
		count := 0
		return backoff.Retry(context.Background(), func() (int, error) {
			count++
			return count, f(iface)
		}, backoff.WithBackOff(&backoff.ExponentialBackOff{
			InitialInterval:     300 * time.Millisecond,
			RandomizationFactor: backoff.DefaultRandomizationFactor,
			Multiplier:          2,
			MaxInterval:         60 * time.Second,
		}), backoff.WithMaxTries(uint(retries)))
	}
	return 1, f(iface)
}

func (i *interfaceListener) increaseErrors(err error, isAttach bool) {
	errName := "AttachUnknownError"
	var tracerErr *tracer.Error
	if errors.As(err, &tracerErr) {
		errName = tracerErr.Name
	} else if !isAttach {
		errName = "DetachUnknownError"
	}
	i.metrics.Errors.WithErrorName("InterfaceEvents", errName, metrics.LowSeverity).Inc()
}

func (i *interfaceListener) attachTC(iface *ifaces.Interface) {
	if count, err := runWithRetries(iface, i.cfg.TCAttachRetries, i.attacher.Register); err != nil {
		i.increaseErrors(err, true)
		ilog.WithField("interface", iface).WithField("retries", count).WithError(err).Warn("interface detected, could not attach TC hook")
		i.metrics.InterfaceEventsCounter.Increase("attach_fail", iface.Name, iface.Index, iface.NSName, iface.MAC, count)
	} else {
		ilog.WithField("interface", iface).WithField("retries", count).Debug("interface detected, TC hook attached")
		i.metrics.InterfaceEventsCounter.Increase("attach_tc", iface.Name, iface.Index, iface.NSName, iface.MAC, count)
	}
}

func (i *interfaceListener) attachTCX(iface *ifaces.Interface) {
	if count, err := runWithRetries(iface, i.cfg.TCAttachRetries, i.attacher.AttachTCX); err != nil {
		i.increaseErrors(err, true)
		ilog.WithField("interface", iface).WithField("retries", count).WithError(err).Warn("interface detected, could not attach TCX hook")
		i.metrics.InterfaceEventsCounter.Increase("attach_fail", iface.Name, iface.Index, iface.NSName, iface.MAC, count)
	} else {
		ilog.WithField("interface", iface).WithField("retries", count).Debug("interface detected, TCX hook attached")
		i.metrics.InterfaceEventsCounter.Increase("attach_tcx", iface.Name, iface.Index, iface.NSName, iface.MAC, count)
	}
}

func (i *interfaceListener) attachAny(iface *ifaces.Interface) {
	if err1 := i.attacher.AttachTCX(iface); err1 != nil {
		i.increaseErrors(err1, true)
		if err2 := i.attacher.Register(iface); err2 != nil {
			ilog.WithField("interface", iface).WithError(err2).Warn("interface detected, could not attach any hook")
			i.metrics.InterfaceEventsCounter.Increase("attach_fail", iface.Name, iface.Index, iface.NSName, iface.MAC, 2)
			return
		}
		ilog.WithField("interface", iface).WithError(err1).Debug("interface detected, could not attach TCX hook, falling back to legacy TC")
		i.metrics.InterfaceEventsCounter.Increase("attach_tc", iface.Name, iface.Index, iface.NSName, iface.MAC, 2)
		return
	}
	ilog.WithField("interface", iface).Debug("interface detected, TCX hook attached")
	i.metrics.InterfaceEventsCounter.Increase("attach_tcx", iface.Name, iface.Index, iface.NSName, iface.MAC, 1)
}

func (i *interfaceListener) detachTC(iface *ifaces.Interface) {
	if count, err := runWithRetries(iface, i.cfg.TCAttachRetries, i.attacher.UnRegister); err != nil {
		i.increaseErrors(err, false)
		ilog.WithField("interface", iface).WithField("retries", count).WithError(err).Warn("interface deleted, could not detach TC hook")
		i.metrics.InterfaceEventsCounter.Increase("detach_fail", iface.Name, iface.Index, iface.NSName, iface.MAC, count)
	} else {
		ilog.WithField("interface", iface).WithField("retries", count).Debug("interface deleted, TC hook detached")
		i.metrics.InterfaceEventsCounter.Increase("detach_tc", iface.Name, iface.Index, iface.NSName, iface.MAC, count)
	}
}

func (i *interfaceListener) detachTCX(iface *ifaces.Interface) {
	if count, err := runWithRetries(iface, i.cfg.TCAttachRetries, i.attacher.DetachTCX); err != nil {
		i.increaseErrors(err, false)
		ilog.WithField("interface", iface).WithField("retries", count).WithError(err).Warn("interface deleted, could not detach TCX hook")
		i.metrics.InterfaceEventsCounter.Increase("detach_fail", iface.Name, iface.Index, iface.NSName, iface.MAC, count)
	} else {
		ilog.WithField("interface", iface).WithField("retries", count).Debug("interface deleted, TCX hook detached")
		i.metrics.InterfaceEventsCounter.Increase("detach_tcx", iface.Name, iface.Index, iface.NSName, iface.MAC, count)
	}
}

func (i *interfaceListener) detachAny(iface *ifaces.Interface) {
	if err1 := i.attacher.DetachTCX(iface); err1 != nil {
		i.increaseErrors(err1, false)
		if err2 := i.attacher.UnRegister(iface); err2 != nil {
			ilog.WithField("interface", iface).WithError(err2).Warn("interface deleted, could not detach any hook")
			i.metrics.InterfaceEventsCounter.Increase("detach_fail", iface.Name, iface.Index, iface.NSName, iface.MAC, 2)
			return
		}
		ilog.WithField("interface", iface).WithError(err1).Debug("interface deleted, could not detach TCX hook, falling back to legacy TC")
		i.metrics.InterfaceEventsCounter.Increase("detach_tc", iface.Name, iface.Index, iface.NSName, iface.MAC, 2)
		return
	}
	ilog.WithField("interface", iface).Debug("interface deleted, TCX hook detached")
	i.metrics.InterfaceEventsCounter.Increase("detach_tcx", iface.Name, iface.Index, iface.NSName, iface.MAC, 1)
}
