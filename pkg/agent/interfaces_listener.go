package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"
)

var ilog = logrus.WithField("component", "agent.Interfaces")

type tcAttacher interface {
	Register(iface *ifaces.Interface) error
	UnRegister(iface *ifaces.Interface) error
	AttachTCX(iface *ifaces.Interface) error
	DetachTCX(iface *ifaces.Interface) error
}

// find a way to coordinate tracer and watcher_poller. when tracer fails to attach, watcher_poller should know that, so it sends again the events next time

type interfaceListener struct {
	attacher tcAttacher
	cfg      *config.Agent
	metrics  *metrics.Metrics
	filter   ifaces.Filter
	requeue  chan retriableEvent
}

type retriableEvent struct {
	ifaces.Event
	attempt   int
	lastError error
}

func createInformer(cfg *config.Agent, m *metrics.Metrics) ifaces.Informer {
	// configure informer for new interfaces
	var informer ifaces.Informer
	switch cfg.ListenInterfaces {
	case config.ListenPoll:
		ilog.WithField("period", cfg.ListenPollPeriod).Info("listening for new interfaces: use polling")
		informer = ifaces.NewPoller(cfg.ListenPollPeriod, cfg.BuffersLength)
	case config.ListenWatch:
		ilog.Info("listening for new interfaces: use watching")
		informer = ifaces.NewWatcher(cfg.BuffersLength, m)
	default:
		ilog.WithField("providedValue", cfg.ListenInterfaces).Warn("wrong interface listen method. Using file watcher as default")
		informer = ifaces.NewWatcher(cfg.BuffersLength, m)
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
		requeue:  make(chan retriableEvent, cfg.BuffersLength),
	}

	go l.start(ctx, ifaceEvents)

	return nil
}

func (i *interfaceListener) start(ctx context.Context, ifaceEvents <-chan ifaces.Event) {
	var attach, detach func(*retriableEvent)
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
			i.onEventReceived(&retriableEvent{Event: event, attempt: 1}, attach, detach)
		case event := <-i.requeue:
			i.onEventReceived(&event, attach, detach)
		}
	}
}

func (i *interfaceListener) onEventReceived(event *retriableEvent, attach, detach func(*retriableEvent)) {
	ilog.WithField("event", event).Debug("received event")
	// ignore interfaces that do not match the user configuration acceptance/exclusion lists
	allowed, err := i.filter.Allowed(event.Interface.Name)
	if err != nil {
		ilog.WithField("interface", event.Interface).Errorf("encountered error determining if interface is allowed: %v", err)
		return
	}
	if !allowed {
		ilog.WithField("interface", event.Interface).Debug("interface does not match the allow/exclusion filters. Ignoring")
		return
	}
	switch event.Type {
	case ifaces.EventAdded:
		attach(event)
	case ifaces.EventDeleted:
		detach(event)
	default:
		ilog.WithField("event", event).Warn("unknown event type")
	}
}

// returns true when completed, false when requeued
func (i *interfaceListener) runWithRetries(event *retriableEvent, f func(*ifaces.Interface) error) (bool, error) {
	if err := f(&event.Interface); err != nil {
		allowRequeue := true
		var tracerErr *tracer.Error
		if errors.As(err, &tracerErr) && tracerErr.DoNotRetry {
			allowRequeue = false
		}
		if allowRequeue && event.attempt < i.cfg.TCAttachRetries {
			// Requeue
			go func() {
				time.Sleep(300 * time.Duration(event.attempt) * time.Millisecond)
				event.attempt++
				event.lastError = err
				i.requeue <- *event
			}()
			return false, nil
		}
		return true, err
	}
	if event.lastError != nil {
		ilog.WithError(event.lastError).Debugf("error eventually resolved")
	}
	return true, nil
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

func (i *interfaceListener) attachTC(event *retriableEvent) {
	if complete, err := i.runWithRetries(event, i.attacher.Register); complete {
		if err != nil {
			i.increaseErrors(err, true)
			ilog.WithField("interface", event.Interface).WithField("retries", event.attempt).WithError(err).Warn("interface detected, could not attach TC hook")
			i.metrics.InterfaceEventsCounter.Increase("attach_fail", event.Interface.Name, event.Interface.Index, event.Interface.NSName, event.Interface.MAC, event.attempt)
		} else {
			ilog.WithField("interface", event.Interface).WithField("retries", event.attempt).Debug("interface detected, TC hook attached")
			i.metrics.InterfaceEventsCounter.Increase("attach_tc", event.Interface.Name, event.Interface.Index, event.Interface.NSName, event.Interface.MAC, event.attempt)
		}
	}
}

func (i *interfaceListener) attachTCX(event *retriableEvent) {
	if complete, err := i.runWithRetries(event, runInNamespace("Attach", i.attacher.AttachTCX)); complete {
		if err != nil {
			i.increaseErrors(err, true)
			ilog.WithField("interface", event.Interface).WithField("retries", event.attempt).WithError(err).Warn("interface detected, could not attach TCX hook")
			i.metrics.InterfaceEventsCounter.Increase("attach_fail", event.Interface.Name, event.Interface.Index, event.Interface.NSName, event.Interface.MAC, event.attempt)
		} else {
			ilog.WithField("interface", event.Interface).WithField("retries", event.attempt).Debug("interface detected, TCX hook attached")
			i.metrics.InterfaceEventsCounter.Increase("attach_tcx", event.Interface.Name, event.Interface.Index, event.Interface.NSName, event.Interface.MAC, event.attempt)
		}
	}
}

func (i *interfaceListener) attachAny(event *retriableEvent) {
	if err1 := runInNamespace("Attach", i.attacher.AttachTCX)(&event.Interface); err1 != nil {
		i.increaseErrors(err1, true)
		if err2 := i.attacher.Register(&event.Interface); err2 != nil {
			ilog.WithField("interface", event.Interface).WithError(err2).Warn("interface detected, could not attach any hook")
			i.metrics.InterfaceEventsCounter.Increase("attach_fail", event.Interface.Name, event.Interface.Index, event.Interface.NSName, event.Interface.MAC, 2)
			return
		}
		ilog.WithField("interface", event.Interface).WithError(err1).Debug("interface detected, could not attach TCX hook, falling back to legacy TC")
		i.metrics.InterfaceEventsCounter.Increase("attach_tc", event.Interface.Name, event.Interface.Index, event.Interface.NSName, event.Interface.MAC, 2)
		return
	}
	ilog.WithField("interface", event.Interface).Debug("interface detected, TCX hook attached")
	i.metrics.InterfaceEventsCounter.Increase("attach_tcx", event.Interface.Name, event.Interface.Index, event.Interface.NSName, event.Interface.MAC, 1)
}

func (i *interfaceListener) detachTC(event *retriableEvent) {
	if complete, err := i.runWithRetries(event, i.attacher.UnRegister); complete {
		if err != nil {
			i.increaseErrors(err, false)
			ilog.WithField("interface", event.Interface).WithField("retries", event.attempt).WithError(err).Warn("interface deleted, could not detach TC hook")
			i.metrics.InterfaceEventsCounter.Increase("detach_fail", event.Interface.Name, event.Interface.Index, event.Interface.NSName, event.Interface.MAC, event.attempt)
		} else {
			ilog.WithField("interface", event.Interface).WithField("retries", event.attempt).Debug("interface deleted, TC hook detached")
			i.metrics.InterfaceEventsCounter.Increase("detach_tc", event.Interface.Name, event.Interface.Index, event.Interface.NSName, event.Interface.MAC, event.attempt)
		}
	}
}

func (i *interfaceListener) detachTCX(event *retriableEvent) {
	if complete, err := i.runWithRetries(event, runInNamespace("Detach", i.attacher.DetachTCX)); complete {
		if err != nil {
			i.increaseErrors(err, false)
			ilog.WithField("interface", event.Interface).WithField("retries", event.attempt).WithError(err).Warn("interface deleted, could not detach TCX hook")
			i.metrics.InterfaceEventsCounter.Increase("detach_fail", event.Interface.Name, event.Interface.Index, event.Interface.NSName, event.Interface.MAC, event.attempt)
		} else {
			ilog.WithField("interface", event.Interface).WithField("retries", event.attempt).Debug("interface deleted, TCX hook detached")
			i.metrics.InterfaceEventsCounter.Increase("detach_tcx", event.Interface.Name, event.Interface.Index, event.Interface.NSName, event.Interface.MAC, event.attempt)
		}
	}
}

func (i *interfaceListener) detachAny(event *retriableEvent) {
	if err1 := runInNamespace("Detach", i.attacher.DetachTCX)(&event.Interface); err1 != nil {
		i.increaseErrors(err1, false)
		if err2 := i.attacher.UnRegister(&event.Interface); err2 != nil {
			ilog.WithField("interface", event.Interface).WithError(err2).Warn("interface deleted, could not detach any hook")
			i.metrics.InterfaceEventsCounter.Increase("detach_fail", event.Interface.Name, event.Interface.Index, event.Interface.NSName, event.Interface.MAC, 2)
			return
		}
		ilog.WithField("interface", event.Interface).WithError(err1).Debug("interface deleted, could not detach TCX hook, falling back to legacy TC")
		i.metrics.InterfaceEventsCounter.Increase("detach_tc", event.Interface.Name, event.Interface.Index, event.Interface.NSName, event.Interface.MAC, 2)
		return
	}
	ilog.WithField("interface", event.Interface).Debug("interface deleted, TCX hook detached")
	i.metrics.InterfaceEventsCounter.Increase("detach_tcx", event.Interface.Name, event.Interface.Index, event.Interface.NSName, event.Interface.MAC, 1)
}

// WARNING: concurrent-unsafe code while setting netns. Caller must ensure this is called sequentially.
func runInNamespace(errPrefix string, inner func(*ifaces.Interface) error) func(*ifaces.Interface) error {
	return func(iface *ifaces.Interface) error {
		if iface.NetNS != netns.None() {
			originalNs, err := netns.Get()
			if err != nil {
				return tracer.NewError(errPrefix+":CantGetNetNS", fmt.Errorf("failed to get current netns: %w", err))
			}
			defer func() {
				if err := netns.Set(originalNs); err != nil {
					ilog.WithError(err).Error("failed to set netns back")
				}
				originalNs.Close()
			}()
			if err = netns.Set(iface.NetNS); err != nil {
				handle, err2 := netns.GetFromName(iface.NSName)
				if err2 != nil {
					return tracer.NewError(errPrefix+":CantSetNetNS-A", fmt.Errorf("failed to setns to %s: %w; NetNS doesn't exist? (%w)", iface.NetNS, err, err2))
				} else if handle != iface.NetNS {
					return tracer.NewError(errPrefix+":CantSetNetNS-B", fmt.Errorf("failed to setns to %s: %w; handle differs (%d != %d)", iface.NetNS, err, handle, iface.NetNS))
				}
				return tracer.NewError(errPrefix+":CantSetNetNS-C", fmt.Errorf("failed to setns to %s: %w", iface.NetNS, err))
			}
		}
		return inner(iface)
	}
}
