package agent

import (
	"context"
	"fmt"

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
	AttachTCX(iface *ifaces.Interface) *tracer.TracerError
	DetachTCX(iface *ifaces.Interface) *tracer.TracerError
}

type interfaceListener struct {
	attacher tcAttacher
	cfg      *config.Agent
	metrics  *metrics.Metrics
	filter   ifaces.Filter
}

// startInterfaceListener uses an informer to check new/deleted network interfaces. For each running
// interface, it registers a flow ebpfFetcher that will forward new flows to the returned channel
func startInterfaceListener(ctx context.Context, attacher tcAttacher, cfg *config.Agent, m *metrics.Metrics) error {
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

	return startWithInformer(ctx, attacher, cfg, m, informer)
}

func startWithInformer(ctx context.Context, attacher tcAttacher, cfg *config.Agent, m *metrics.Metrics, informer ifaces.Informer) error {
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
	for {
		select {
		case <-ctx.Done():
			ilog.Debug("stopping interfaces' listener")
			return
		case event := <-ifaceEvents:
			ilog.WithField("event", event).Debug("received event")
			switch event.Type {
			case ifaces.EventAdded:
				i.onInterfaceAdded(&event.Interface)
			case ifaces.EventDeleted:
				i.onInterfaceDeleted(&event.Interface)
			default:
				ilog.WithField("event", event).Warn("unknown event type")
			}
		}
	}
}

func (i *interfaceListener) onInterfaceAdded(iface *ifaces.Interface) {
	// ignore interfaces that do not match the user configuration acceptance/exclusion lists
	allowed, err := i.filter.Allowed(iface.Name)
	if err != nil {
		alog.WithField("interface", iface).Errorf("encountered error determining if interface is allowed: %v", err)
		return
	}
	if !allowed {
		alog.WithField("interface", iface).Debug("interface does not match the allow/exclusion filters. Ignoring")
		return
	}
	// if iface.Index == 0 && model.AllZerosMac(iface.MAC) && iface.Name == "" {
	// 	alog.WithField("interface", iface).Debug("ignoring invalid interface event")
	// 	return
	// }
	if err1 := i.attacher.AttachTCX(iface); err1 != nil {
		i.metrics.Errors.WithErrorName("InterfaceEvents", err1.Name, metrics.LowSeverity).Inc()
		if err2 := i.attacher.Register(iface); err2 != nil {
			alog.WithField("interface", iface).WithError(err2).Warn("interface detected, could not attach any hook")
			i.metrics.InterfaceEventsCounter.Increase("attach_fail", iface.Name, iface.Index, iface.NSName, iface.MAC)
			return
		}
		// iface.HookType = ifaces.TCHook
		alog.WithField("interface", iface).WithError(err1).Debug("interface detected, could not attach TCX hook, falling back to legacy TC")
		i.metrics.InterfaceEventsCounter.Increase("attach_tc", iface.Name, iface.Index, iface.NSName, iface.MAC)
		return
	}
	// iface.HookType = ifaces.TCXHook
	alog.WithField("interface", iface).Debug("interface detected, TCX hook attached")
	i.metrics.InterfaceEventsCounter.Increase("attach_tcx", iface.Name, iface.Index, iface.NSName, iface.MAC)
}

func (i *interfaceListener) onInterfaceDeleted(iface *ifaces.Interface) {
	// ignore interfaces that do not match the user configuration acceptance/exclusion lists
	allowed, err := i.filter.Allowed(iface.Name)
	if err != nil {
		alog.WithField("interface", iface).Errorf("encountered error determining if interface is allowed: %v", err)
		return
	}
	if !allowed {
		alog.WithField("interface", iface).Debug("interface does not match the allow/exclusion filters. Ignoring")
		return
	}
	// switch iface.HookType {
	// case ifaces.TCHook:
	// 	if err := f.ebpf.UnRegister(iface); err != nil {
	// 		alog.WithField("interface", iface).WithError(err).Warn("interface deleted, could not detach TC hook")
	// 		f.metrics.InterfaceEventsCounter.Increase("detach_tc_fail", iface.Name, iface.Index, iface.NSName, iface.MAC)
	// 		f.metrics.Errors.WithErrorName("InterfaceEvents", "CantDetachTC", metrics.MediumSeverity).Inc()
	// 		return
	// 	}
	// 	alog.WithField("interface", iface).Debug("interface deleted, TC hook detached")
	// 	f.metrics.InterfaceEventsCounter.Increase("detach_tc", iface.Name, iface.Index, iface.NSName, iface.MAC)
	// case ifaces.TCXHook:
	// 	if err := f.ebpf.DetachTCX(iface); err != nil {
	// 		f.metrics.Errors.WithErrorName("InterfaceEvents", err.Name, metrics.MediumSeverity).Inc()
	// 		alog.WithField("interface", iface).WithError(err).Warn("interface deleted, could not detach TCX hook")
	// 		f.metrics.InterfaceEventsCounter.Increase("detach_tcx_fail", iface.Name, iface.Index, iface.NSName, iface.MAC)
	// 		return
	// 	}
	// 	alog.WithField("interface", iface).Debug("interface deleted, TCX hook detached")
	// 	f.metrics.InterfaceEventsCounter.Increase("detach_tcx", iface.Name, iface.Index, iface.NSName, iface.MAC)
	// case ifaces.Unset:
	alog.WithField("interface", iface).Warn("interface deleted and no known hook attached, trying to detach anyway...")
	if err1 := i.attacher.DetachTCX(iface); err1 != nil {
		i.metrics.Errors.WithErrorName("InterfaceEvents", err1.Name+" (unset)", metrics.MediumSeverity).Inc()
		if err2 := i.attacher.UnRegister(iface); err2 != nil {
			alog.WithField("interface", iface).WithError(err2).Warn("interface deleted, could not detach any hook")
			i.metrics.InterfaceEventsCounter.Increase("unset_detach_fail", iface.Name, iface.Index, iface.NSName, iface.MAC)
			return
		}
		alog.WithField("interface", iface).WithError(err1).Debug("interface deleted, could not detach TCX hook, falling back to legacy TC")
		i.metrics.InterfaceEventsCounter.Increase("unset_detach_tc", iface.Name, iface.Index, iface.NSName, iface.MAC)
		return
	}
	alog.WithField("interface", iface).Debug("interface deleted, TCX hook detached")
	i.metrics.InterfaceEventsCounter.Increase("unset_detach_tcx", iface.Name, iface.Index, iface.NSName, iface.MAC)
	// }
}
