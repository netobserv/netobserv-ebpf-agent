package flows

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/kernel"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/attach"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/internal/netattach"
	"github.com/prometheus/client_golang/prometheus"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gavv/monotime"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var log = logrus.WithField("component", "ebpf.FlowFetcher")

// Fetcher reads and forwards the Flows from the Traffic Control hooks in the eBPF kernel space.
// It provides access both to flows that are aggregated in the kernel space (via PerfCPU hashmap)
// and to flows that are forwarded by the kernel via ringbuffer because could not be aggregated
// in the map
type Fetcher struct {
	objects                     *ebpf.BpfObjects
	qdiscs                      map[ifaces.InterfaceKey]*netlink.GenericQdisc
	egressFilters               map[ifaces.InterfaceKey]*netlink.BpfFilter
	ingressFilters              map[ifaces.InterfaceKey]*netlink.BpfFilter
	ringbufReader               *ringbuf.Reader
	pktDropsTracePoint          link.Link
	rttFentryLink               link.Link
	rttKprobeLink               link.Link
	egressTCXLink               map[ifaces.InterfaceKey]link.Link
	ingressTCXLink              map[ifaces.InterfaceKey]link.Link
	netkitPrimaryLinks          map[ifaces.InterfaceKey]link.Link
	netkitPeerLinks             map[ifaces.InterfaceKey]link.Link
	egressTCXAnchor             link.Anchor
	ingressTCXAnchor            link.Anchor
	networkEventsMonitoringLink link.Link
	nfNatManIPLink              link.Link
	xfrmInputKretProbeLink      link.Link
	xfrmOutputKretProbeLink     link.Link
	xfrmInputKProbeLink         link.Link
	xfrmOutputKProbeLink        link.Link
	sslUprobe                   link.Link
	sslDataEventsReader         *ringbuf.Reader
	lookupAndDeleteSupported    bool
	pinDir                      string
	config                      *tracer.FetcherConfig
}

//nolint:cyclop // BPF load paths branch on kernel features and optional hooks.
func NewFetcher(cfg *tracer.FetcherConfig, m *metrics.Metrics) (*Fetcher, error) {
	var pktDropsLink, networkEventsMonitoringLink, rttFentryLink, rttKprobeLink link.Link
	var nfNatManIPLink, xfrmInputKretProbeLink, xfrmOutputKretProbeLink link.Link
	var xfrmInputKProbeLink, xfrmOutputKProbeLink link.Link
	var sslUprobe link.Link
	var sslDataEvents *ringbuf.Reader
	var err error
	objects := ebpf.BpfObjects{}
	var pinDir string
	var filter *attach.Filter
	if len(cfg.FilterConfig) > 0 {
		filter = attach.NewFilter(cfg.FilterConfig)
	}

	if !cfg.EbpfProgramManagerMode {
		if err := rlimit.RemoveMemlock(); err != nil {
			log.WithError(err).
				Warn("can't remove mem lock. The agent will not be able to start eBPF programs")
		}
		spec, err := ebpf.LoadBpf()
		if err != nil {
			return nil, fmt.Errorf("loading BPF data: %w", err)
		}

		// Resize maps according to user-provided configuration
		spec.Maps[ebpf.BpfMapAggregatedFlows].MaxEntries = uint32(cfg.CacheMaxFlows)
		sizeMapForFeature(spec, ebpf.BpfMapAggregatedFlowsDns, cfg.Flows.EnableDNSTracking, cfg.CacheMaxFlows)
		sizeMapForFeature(spec, ebpf.BpfMapAggregatedFlowsNetworkEvents, cfg.Flows.EnableNetworkEventsMonitoring, cfg.CacheMaxFlows)
		sizeMapForFeature(spec, ebpf.BpfMapAggregatedFlowsPktDrop, cfg.Flows.EnablePktDrops, cfg.CacheMaxFlows)
		sizeMapForFeature(spec, ebpf.BpfMapAggregatedFlowsXlat, cfg.Flows.EnablePktTranslationTracking, cfg.CacheMaxFlows)
		sizeMapForFeature(spec, ebpf.BpfMapAdditionalFlowMetrics, cfg.Flows.EnableRTT || cfg.Flows.EnableIPsecTracking, cfg.CacheMaxFlows)

		ringbufMinSize := uint32(os.Getpagesize())

		// Minimize direct-flows ringbuf if unused
		if !cfg.Flows.EnableFlowsRingbufFallback {
			spec.Maps[ebpf.BpfMapDirectFlows].MaxEntries = ringbufMinSize
		}
		// Minimize SSL maps if SSL is disabled
		if !cfg.Flows.EnableOpenSSLTracking {
			spec.Maps[ebpf.BpfMapSslDataEventMap].MaxEntries = ringbufMinSize
		}
		// remove pinning from all maps
		for _, m := range []string{
			ebpf.BpfMapAggregatedFlows,
			ebpf.BpfMapAggregatedFlowsDns,
			ebpf.BpfMapAggregatedFlowsNetworkEvents,
			ebpf.BpfMapAggregatedFlowsPktDrop,
			ebpf.BpfMapAggregatedFlowsXlat,
			ebpf.BpfMapAdditionalFlowMetrics,
			ebpf.BpfMapDirectFlows,
			ebpf.BpfMapDnsFlows,
			ebpf.BpfMapFilterMap,
			ebpf.BpfMapPeerFilterMap,
			ebpf.BpfMapGlobalCounters,
			ebpf.BpfMapIpsecIngressMap,
			ebpf.BpfMapIpsecEgressMap,
			ebpf.BpfMapSslDataEventMap,
			ebpf.BpfMapDnsNameMap,
			ebpf.BpfMapQuicFlows,
		} {
			spec.Maps[m].Pinning = 0
		}

		if err := configureFlowSpecVariables(spec, cfg, filter); err != nil {
			return nil, fmt.Errorf("loading flow spec variables: %w", err)
		}

		oldKernel := kernel.IsKernelOlderThan("5.14.0")
		if oldKernel {
			log.Infof("kernel older than 5.14.0 detected: not all hooks are supported")
		}
		rtOldKernel := kernel.IsRealTimeKernel() && kernel.IsKernelOlderThan("5.14.0-292")
		if rtOldKernel {
			log.Infof("kernel is realtime and older than 5.14.0-292 not all hooks are supported")
		}
		supportNetworkEvents := !kernel.IsKernelOlderThan("5.14.0-570")
		supportNetkit := !kernel.IsKernelOlderThan("6.7.0")
		objects, err = kernelSpecificLoadAndAssign(oldKernel, rtOldKernel, supportNetworkEvents, supportNetkit, spec, pinDir)
		if err != nil {
			return nil, err
		}

		if cfg.Flows.EnablePktDrops && !oldKernel && !rtOldKernel {
			pktDropsLink, err = link.Tracepoint("skb", ebpf.BpfProgKfreeSkb, objects.KfreeSkb, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to attach the BPF program to kfree_skb tracepoint: %w", err)
			}
		}

		if cfg.Flows.EnableNetworkEventsMonitoring {
			if supportNetworkEvents {
				log.Infof("kernel is 5.14.0-570 detected: use kapi network_events_monitoring hook")
				networkEventsMonitoringLink, err = link.Kprobe(netattach.NetworkEventsMonitoringHook, objects.NetworkEventsMonitoring, nil)
				if err != nil {
					return nil, fmt.Errorf("failed to attach the BPF program network events monitoring kprobe: %w", err)
				}
			} else {
				log.Infof("kernel older than 5.14.0-570 detected: it does not support network_events_monitoring hook, skip")
			}
		}

		if cfg.Flows.EnableRTT {
			if !oldKernel {
				rttFentryLink, err = link.AttachTracing(link.TracingOptions{
					Program: objects.BpfPrograms.TcpRcvFentry,
				})
				if err == nil {
					goto next
				}
				log.Warningf("failed to attach the BPF program to tcpReceiveFentry: %v fallback to use kprobe", err)
				// Fall through to use kprobe
			}
			// try to use kprobe for older kernels
			if !rtOldKernel {
				rttKprobeLink, err = link.Kprobe("tcp_rcv_established", objects.TcpRcvKprobe, nil)
				if err != nil {
					log.Warningf("failed to attach the BPF program to kprobe: %v", err)
					return nil, fmt.Errorf("failed to attach the BPF program to tcpReceiveKprobe: %w", err)
				}
			}
		}
	next:
		if cfg.Flows.EnablePktTranslationTracking {
			nfNatManIPLink, err = link.Kprobe("nf_nat_manip_pkt", objects.TrackNatManipPkt, nil)
			if err != nil {
				log.Warningf("failed to attach the BPF program to nat_manip kprobe: %v", err)
				return nil, fmt.Errorf("failed to attach the BPF program to nat_manip kprobe: %w", err)
			}
		}

		if cfg.Flows.EnableIPsecTracking {
			xfrmInputKProbeLink, err = link.Kprobe("xfrm_input", objects.XfrmInputKprobe, nil)
			if err != nil {
				log.Warningf("failed to attach the BPF KProbe program to xfrm_input: %v", err)
				return nil, fmt.Errorf("failed to attach the BPF KProbe program to xfrm_input: %w", err)
			}
			xfrmOutputKProbeLink, err = link.Kprobe("xfrm_output", objects.XfrmOutputKprobe, nil)
			if err != nil {
				log.Warningf("failed to attach the BPF KProbe program to xfrm_output: %v", err)
				return nil, fmt.Errorf("failed to attach the BPF KProbe program to xfrm_output: %w", err)
			}
			xfrmInputKretProbeLink, err = link.Kretprobe("xfrm_input", objects.XfrmInputKretprobe, nil)
			if err != nil {
				log.Warningf("failed to attach the BPF KretProbe program to xfrm_input: %v", err)
				return nil, fmt.Errorf("failed to attach the BPF KretProbe program to xfrm_input: %w", err)
			}
			xfrmOutputKretProbeLink, err = link.Kretprobe("xfrm_output", objects.XfrmOutputKretprobe, nil)
			if err != nil {
				log.Warningf("failed to attach the BPF KretProbe program to xfrm_output: %v", err)
				return nil, fmt.Errorf("failed to attach the BPF KretProbe program to xfrm_output: %w", err)
			}
		}

		// Setup SSL tracking if enabled
		if cfg.Flows.EnableOpenSSLTracking {
			// Read SSL data events from ringbuf
			sslDataEvents, err = ringbuf.NewReader(objects.BpfMaps.SslDataEventMap)
			if err != nil {
				return nil, fmt.Errorf("accessing SSL data event ringbuffer: %w", err)
			}

			// Attach SSL uprobes
			sslWriteLink, err := link.OpenExecutable(cfg.Flows.OpenSSLPath)
			if err != nil {
				return nil, fmt.Errorf("failed to open executable %s: %w", cfg.Flows.OpenSSLPath, err)
			}
			sslUprobe, err = sslWriteLink.Uprobe("SSL_write", objects.ProbeEntrySSL_write, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to attach SSL_write uprobe: %w", err)
			}
			log.Infof("SSL tracking enabled with library: %s", cfg.Flows.OpenSSLPath)
		}

	} else {
		pinDir = cfg.BpfManBpfFSPath
		opts := &cilium.LoadPinOptions{
			ReadOnly:  false,
			WriteOnly: false,
			Flags:     0,
		}

		loadPinnedMapInto := func(msg, mapName string, dst **cilium.Map) error {
			log.Infof("BPFManager mode: loading %s pinned maps", msg)
			mPath := path.Join(pinDir, mapName)
			m, err := cilium.LoadPinnedMap(mPath, opts)
			if err != nil {
				return fmt.Errorf("failed to load %s: %w", mPath, err)
			}
			*dst = m
			return nil
		}

		if err := loadPinnedMapInto("aggregated flows", ebpf.BpfMapAggregatedFlows, &objects.BpfMaps.AggregatedFlows); err != nil {
			return nil, err
		}

		if err := loadPinnedMapInto("additional flow metrics", ebpf.BpfMapAdditionalFlowMetrics, &objects.BpfMaps.AdditionalFlowMetrics); err != nil {
			return nil, err
		}

		if err := loadPinnedMapInto("direct flows", ebpf.BpfMapDirectFlows, &objects.BpfMaps.DirectFlows); err != nil {
			return nil, err
		}

		if err := loadPinnedMapInto("global counters", ebpf.BpfMapGlobalCounters, &objects.BpfMaps.GlobalCounters); err != nil {
			return nil, err
		}

		if cfg.Flows.EnableDNSTracking {
			if err := loadPinnedMapInto("aggregated flow DNS", ebpf.BpfMapAggregatedFlowsDns, &objects.BpfMaps.AggregatedFlowsDns); err != nil {
				return nil, err
			}

			if err := loadPinnedMapInto("DNS flows", ebpf.BpfMapDnsFlows, &objects.BpfMaps.DnsFlows); err != nil {
				return nil, err
			}

			if err := loadPinnedMapInto("DNS name", ebpf.BpfMapDnsNameMap, &objects.BpfMaps.DnsNameMap); err != nil {
				return nil, err
			}
		}

		if cfg.Flows.EnablePktDrops {
			if err := loadPinnedMapInto("aggregated flow pkt drops", ebpf.BpfMapAggregatedFlowsPktDrop, &objects.BpfMaps.AggregatedFlowsPktDrop); err != nil {
				return nil, err
			}
		}

		if cfg.Flows.EnableNetworkEventsMonitoring {
			if err := loadPinnedMapInto("aggregated flow network events", ebpf.BpfMapAggregatedFlowsNetworkEvents, &objects.BpfMaps.AggregatedFlowsNetworkEvents); err != nil {
				return nil, err
			}
		}

		if cfg.Flows.EnablePktTranslationTracking {
			if err := loadPinnedMapInto("aggregated flow translation", ebpf.BpfMapAggregatedFlowsXlat, &objects.BpfMaps.AggregatedFlowsXlat); err != nil {
				return nil, err
			}
		}

		if filter != nil {
			if err := loadPinnedMapInto("filter", ebpf.BpfMapFilterMap, &objects.BpfMaps.FilterMap); err != nil {
				return nil, err
			}
			if err := loadPinnedMapInto("peerfilter", ebpf.BpfMapPeerFilterMap, &objects.BpfMaps.PeerFilterMap); err != nil {
				return nil, err
			}
		}

		if cfg.Flows.EnableIPsecTracking {
			if err := loadPinnedMapInto("skb input", ebpf.BpfMapIpsecIngressMap, &objects.BpfMaps.IpsecIngressMap); err != nil {
				return nil, err
			}
			if err := loadPinnedMapInto("skb output", ebpf.BpfMapIpsecEgressMap, &objects.BpfMaps.IpsecEgressMap); err != nil {
				return nil, err
			}
		}

		// Only load SSL map if OpenSSL tracking is enabled
		if cfg.Flows.EnableOpenSSLTracking {
			if err := loadPinnedMapInto("SSL data event", ebpf.BpfMapSslDataEventMap, &objects.BpfMaps.SslDataEventMap); err != nil {
				return nil, err
			}

			// Initialize the ringbuffer reader for SSL events
			sslDataEvents, err = ringbuf.NewReader(objects.BpfMaps.SslDataEventMap)
			if err != nil {
				return nil, fmt.Errorf("accessing SSL data event ringbuffer: %w", err)
			}
		}

		if cfg.Flows.QUICTrackingMode != 0 {
			if err := loadPinnedMapInto("QUIC flows", ebpf.BpfMapQuicFlows, &objects.BpfMaps.QuicFlows); err != nil {
				return nil, err
			}
		}
	}

	if filter != nil {
		if err := filter.ProgramFilter(&objects); err != nil {
			return nil, fmt.Errorf("programming flow filter: %w", err)
		}
	}

	flows, err := ringbuf.NewReader(objects.BpfMaps.DirectFlows)
	if err != nil {
		return nil, fmt.Errorf("accessing to ringbuffer: %w", err)
	}

	qdiscs := map[ifaces.InterfaceKey]*netlink.GenericQdisc{}
	egressTCXLink := map[ifaces.InterfaceKey]link.Link{}
	ingressTCXLink := map[ifaces.InterfaceKey]link.Link{}
	m.CreateInterfaceBufferGauge("qdiscs", func() float64 { return float64(len(qdiscs)) })
	m.CreateInterfaceBufferGauge("egress-tcx-links", func() float64 { return float64(len(egressTCXLink)) })
	m.CreateInterfaceBufferGauge("ingress-tcx-links", func() float64 { return float64(len(ingressTCXLink)) })

	return &Fetcher{
		objects:                     &objects,
		ringbufReader:               flows,
		egressFilters:               map[ifaces.InterfaceKey]*netlink.BpfFilter{},
		ingressFilters:              map[ifaces.InterfaceKey]*netlink.BpfFilter{},
		qdiscs:                      qdiscs,
		pktDropsTracePoint:          pktDropsLink,
		rttFentryLink:               rttFentryLink,
		rttKprobeLink:               rttKprobeLink,
		nfNatManIPLink:              nfNatManIPLink,
		xfrmInputKretProbeLink:      xfrmInputKretProbeLink,
		xfrmOutputKretProbeLink:     xfrmOutputKretProbeLink,
		xfrmInputKProbeLink:         xfrmInputKProbeLink,
		xfrmOutputKProbeLink:        xfrmOutputKProbeLink,
		sslUprobe:                   sslUprobe,
		sslDataEventsReader:         sslDataEvents,
		egressTCXLink:               egressTCXLink,
		ingressTCXLink:              ingressTCXLink,
		egressTCXAnchor:             netattach.TCXAnchor(cfg.TCXAttachAnchorEgress),
		ingressTCXAnchor:            netattach.TCXAnchor(cfg.TCXAttachAnchorIngress),
		netkitPrimaryLinks:          map[ifaces.InterfaceKey]link.Link{},
		netkitPeerLinks:             map[ifaces.InterfaceKey]link.Link{},
		networkEventsMonitoringLink: networkEventsMonitoringLink,
		lookupAndDeleteSupported:    true, // this will be turned off later if found to be not supported
		pinDir:                      pinDir,
		config:                      cfg,
	}, nil
}

func (m *Fetcher) AttachTCX(iface *ifaces.Interface) error {
	// setns is not thread-safe, so we need to lock the OS thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	handle, err := netlink.NewHandleAt(iface.NetNS)
	if err != nil {
		return tracer.NewError("Attach:CantCreateHandle", fmt.Errorf("failed to create handle for netns (%s): %w", iface.NetNS.String(), err))
	}
	defer handle.Close()

	lnk, err := handle.LinkByIndex(iface.Index)
	if err != nil {
		return tracer.NewError("Attach:CantLookupLink", fmt.Errorf("failed to lookup interface %d (%s): %w", iface.Index, iface.Name, err))
	}
	if n, ok := lnk.(*netlink.Netkit); ok && n.Type() == "netkit" {
		log.WithField("iface", iface.Name).Debug("detected netkit interface; attaching via netkit hooks")
		return m.registerNetkit(iface)
	}

	if m.config.EnableEgress {
		egrLink, err := m.attachTCXOnDirection(iface, "Egress", m.objects.BpfPrograms.TcxEgressFlowParse, cilium.AttachTCXEgress, m.egressTCXAnchor)
		if err != nil {
			return err
		}
		m.egressTCXLink[iface.InterfaceKey] = egrLink
	}

	if m.config.EnableIngress {
		ingLink, err := m.attachTCXOnDirection(iface, "Ingress", m.objects.BpfPrograms.TcxIngressFlowParse, cilium.AttachTCXIngress, m.ingressTCXAnchor)
		if err != nil {
			return err
		}
		m.ingressTCXLink[iface.InterfaceKey] = ingLink
	}

	return nil
}

func (m *Fetcher) attachTCXOnDirection(iface *ifaces.Interface, dirName string, prg *cilium.Program, attach cilium.AttachType, anchor link.Anchor) (link.Link, error) {
	ilog := log.WithField("iface", iface)

	lnk, err := link.AttachTCX(link.TCXOptions{
		Program:   prg,
		Attach:    attach,
		Interface: iface.Index,
		Anchor:    anchor,
	})
	if err != nil {
		errPrefix := "Attach" + dirName
		if errors.Is(err, fs.ErrExist) {
			// The interface already has a TCX hook
			log.WithField("iface", iface.Name).Debugf("interface already has a TCX %s hook ignore", dirName)
			if q, err := link.QueryPrograms(link.QueryOptions{
				Target: iface.Index,
				Attach: attach,
			}); err == nil {
				for _, id := range q.Programs {
					linkID, ok := id.LinkID()
					if !ok {
						return nil, tracer.NewError(errPrefix+":CantGetLinkID", fmt.Errorf("failed to get linkID for %s: %w", iface.Name, err))
					}
					if lnk, err = link.NewFromID(linkID); err != nil {
						return nil, tracer.NewError(errPrefix+":CantCreateLinkID", fmt.Errorf("failed to get link for %s flow to %s: %w", dirName, iface.Name, err))
					}
					ilog.WithField("link", linkID).Debugf("attaching %s flow to link", dirName)
				}
			} else {
				return nil, tracer.NewError(errPrefix+":CantQueryTCX", fmt.Errorf("failed to query TCX %s flow to %s: %w", dirName, iface.Name, err))
			}
		} else {
			return nil, tracer.NewError(errPrefix+":CantAttachTCX", fmt.Errorf("failed to attach TCX %s: %w", dirName, err))
		}
	}
	ilog.WithField("interface", iface.Name).Debugf("successfully attach TCX %s hook link: %v", dirName, lnk)
	return lnk, nil
}

func (m *Fetcher) DetachTCX(iface *ifaces.Interface) error {
	ilog := log.WithField("iface", iface)
	var oneErr error

	hasNetkitLink := m.netkitPrimaryLinks[iface.InterfaceKey] != nil || m.netkitPeerLinks[iface.InterfaceKey] != nil
	if hasNetkitLink {
		if l := m.netkitPrimaryLinks[iface.InterfaceKey]; l != nil {
			if err := l.Close(); err != nil {
				oneErr = tracer.NewErrorNoRetry("Detach:CantCloseNetkitPrimaryLink", fmt.Errorf("failed to close netkit primary link: %w", err))
			}
		}
		if l := m.netkitPeerLinks[iface.InterfaceKey]; l != nil {
			if err := l.Close(); err != nil {
				oneErr = tracer.NewErrorNoRetry("Detach:CantCloseNetkitPeerLink", fmt.Errorf("failed to close netkit peer link: %w", err))
			}
		}
		delete(m.netkitPrimaryLinks, iface.InterfaceKey)
		delete(m.netkitPeerLinks, iface.InterfaceKey)
		return oneErr
	}

	if m.config.EnableEgress {
		if l := m.egressTCXLink[iface.InterfaceKey]; l != nil {
			if err := l.Close(); err != nil {
				oneErr = tracer.NewErrorNoRetry("DetachEgress:CantCloseLink", fmt.Errorf("TCX: failed to close egress link: %w", err))
			} else {
				ilog.WithField("interface", iface.Name).Debugf("successfully detach egressTCX hook link: %v", m.egressTCXLink[iface.InterfaceKey])
			}
		} else {
			oneErr = tracer.NewErrorNoRetry("DetachEgress:TCXNoLink", fmt.Errorf("egress link not found for interface %v", iface.Name))
		}
		delete(m.egressTCXLink, iface.InterfaceKey)
	}

	if m.config.EnableIngress {
		if l := m.ingressTCXLink[iface.InterfaceKey]; l != nil {
			if err := l.Close(); err != nil {
				oneErr = tracer.NewErrorNoRetry("DetachIngress:CantCloseLink", fmt.Errorf("TCX: failed to close ingress link: %w", err))
			} else {
				ilog.WithField("interface", iface.Name).Debugf("successfully detach ingressTCX hook link: %v", m.ingressTCXLink[iface.InterfaceKey])
			}
		} else {
			oneErr = tracer.NewErrorNoRetry("DetachIngress:TCXNoLink", fmt.Errorf("ingress link not found for interface %v", iface.Name))
		}
		delete(m.ingressTCXLink, iface.InterfaceKey)
	}

	return oneErr
}

func (m *Fetcher) UnRegister(iface *ifaces.Interface) error {
	// netkit links are not automatically removed; close them explicitly.
	if l := m.netkitPrimaryLinks[iface.InterfaceKey]; l != nil {
		_ = l.Close()
	}
	if l := m.netkitPeerLinks[iface.InterfaceKey]; l != nil {
		_ = l.Close()
	}
	delete(m.netkitPrimaryLinks, iface.InterfaceKey)
	delete(m.netkitPeerLinks, iface.InterfaceKey)

	// qdiscs, ingress and egress filters are automatically deleted so we don't need to
	// specifically detach them from the ebpfFetcher
	return netattach.Unregister(iface, ebpf.BpfProgTcIngressFlowParse, ebpf.BpfProgTcEgressFlowParse, log)
}

// Register and links the eBPF fetcher into the system. The program should invoke Unregister
// before exiting.
func (m *Fetcher) Register(iface *ifaces.Interface) error {
	ilog := log.WithField("iface", iface)
	handle, err := netlink.NewHandleAt(iface.NetNS)
	if err != nil {
		return fmt.Errorf("failed to create handle for netns (%s): %w", iface.NetNS.String(), err)
	}
	defer handle.Close()

	// Load pre-compiled programs and maps into the kernel, and rewrites the configuration
	ipvlan, err := handle.LinkByIndex(iface.Index)
	if err != nil {
		return fmt.Errorf("failed to lookup ipvlan device %d (%s): %w", iface.Index, iface.Name, err)
	}

	// netkit devices support native BPF attach points (netkit/primary, netkit/peer).
	// Prefer those over TC filters/qdiscs when the interface is netkit.
	if n, ok := ipvlan.(*netlink.Netkit); ok && n.Type() == "netkit" {
		ilog.WithField("linkType", ipvlan.Type()).Debug("detected netkit interface; attaching via netkit hooks")
		// Remove any stale TC filters from previous runs (best-effort).
		if err := netattach.Unregister(iface, ebpf.BpfProgTcIngressFlowParse, ebpf.BpfProgTcEgressFlowParse, log); err != nil {
			ilog.WithError(err).Debug("failed to remove stale tc filters before netkit attach")
		}
		return m.registerNetkit(iface)
	}

	qdiscAttrs := netlink.QdiscAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: qdiscAttrs,
		QdiscType:  netattach.QdiscType,
	}
	if err := handle.QdiscDel(qdisc); err == nil {
		ilog.Warn("qdisc clsact already existed. Deleted it")
	}
	if err := handle.QdiscAdd(qdisc); err != nil {
		if errors.Is(err, fs.ErrExist) {
			ilog.WithError(err).Warn("qdisc clsact already exists. Ignoring")
		} else {
			return fmt.Errorf("failed to create clsact qdisc on %d (%s): %w", iface.Index, iface.Name, err)
		}
	}
	m.qdiscs[iface.InterfaceKey] = qdisc

	// Remove previously installed filters
	if err := netattach.Unregister(iface, ebpf.BpfProgTcIngressFlowParse, ebpf.BpfProgTcEgressFlowParse, log); err != nil {
		return fmt.Errorf("failed to remove previous filters: %w", err)
	}

	if err := m.registerEgress(iface, ipvlan, handle); err != nil {
		return err
	}

	return m.registerIngress(iface, ipvlan, handle)
}

func (m *Fetcher) registerEgress(iface *ifaces.Interface, ipvlan netlink.Link, handle *netlink.Handle) error {
	ilog := log.WithField("iface", iface)
	if !m.config.EnableEgress {
		ilog.Debug("ignoring egress traffic, according to user configuration")
		return nil
	}
	// Fetch events on egress
	egressAttrs := netlink.FilterAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  3,
		Priority:  1,
	}
	egressFilter := &netlink.BpfFilter{
		FilterAttrs:  egressAttrs,
		Fd:           m.objects.TcEgressFlowParse.FD(),
		Name:         ebpf.BpfProgTcEgressFlowParse,
		DirectAction: true,
	}
	if err := handle.FilterDel(egressFilter); err == nil {
		ilog.Warn("egress filter already existed. Deleted it")
	}
	if err := handle.FilterAdd(egressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			ilog.WithError(err).Warn("egress filter already exists. Ignoring")
		} else {
			return fmt.Errorf("failed to create egress filter: %w", err)
		}
	}
	m.egressFilters[iface.InterfaceKey] = egressFilter
	return nil
}

func (m *Fetcher) registerIngress(iface *ifaces.Interface, ipvlan netlink.Link, handle *netlink.Handle) error {
	ilog := log.WithField("iface", iface)
	if !m.config.EnableIngress {
		ilog.Debug("ignoring ingress traffic, according to user configuration")
		return nil
	}
	// Fetch events on ingress
	ingressAttrs := netlink.FilterAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	ingressFilter := &netlink.BpfFilter{
		FilterAttrs:  ingressAttrs,
		Fd:           m.objects.TcIngressFlowParse.FD(),
		Name:         ebpf.BpfProgTcIngressFlowParse,
		DirectAction: true,
	}
	if err := handle.FilterDel(ingressFilter); err == nil {
		ilog.Warn("ingress filter already existed. Deleted it")
	}
	if err := handle.FilterAdd(ingressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			ilog.WithError(err).Warn("ingress filter already exists. Ignoring")
		} else {
			return fmt.Errorf("failed to create ingress filter: %w", err)
		}
	}
	m.ingressFilters[iface.InterfaceKey] = ingressFilter
	return nil
}

func (m *Fetcher) registerNetkit(iface *ifaces.Interface) error {
	ilog := log.WithField("iface", iface)
	return netattach.WithNetNS(iface.NetNS, func() error {
		// Attach on primary side (draft mapping: EGRESS).
		if m.config.EnableEgress {
			if m.objects.BpfPrograms.NetkitPrimaryFlowParse == nil {
				return fmt.Errorf("netkit primary program not loaded")
			}
			lnk, err := link.AttachNetkit(link.NetkitOptions{
				Program:   m.objects.BpfPrograms.NetkitPrimaryFlowParse,
				Attach:    cilium.AttachNetkitPrimary,
				Interface: iface.Index,
			})
			if err != nil {
				if errors.Is(err, fs.ErrExist) {
					ilog.Debug("netkit primary link already exists; ignoring")
				} else {
					return fmt.Errorf("failed to attach netkit primary: %w", err)
				}
			} else {
				m.netkitPrimaryLinks[iface.InterfaceKey] = lnk
			}
		}

		// Attach on peer side (draft mapping: INGRESS).
		if m.config.EnableIngress {
			if m.objects.BpfPrograms.NetkitPeerFlowParse == nil {
				return fmt.Errorf("netkit peer program not loaded")
			}
			lnk, err := link.AttachNetkit(link.NetkitOptions{
				Program:   m.objects.BpfPrograms.NetkitPeerFlowParse,
				Attach:    cilium.AttachNetkitPeer,
				Interface: iface.Index,
			})
			if err != nil {
				if errors.Is(err, fs.ErrExist) {
					ilog.Debug("netkit peer link already exists; ignoring")
				} else {
					return fmt.Errorf("failed to attach netkit peer: %w", err)
				}
			} else {
				m.netkitPeerLinks[iface.InterfaceKey] = lnk
			}
		}

		return nil
	})
}

// Close the eBPF fetcher from the system.
// We don't need a "Close(iface)" method because the filters and qdiscs
// are automatically removed when the interface is down
// nolint:cyclop
func (m *Fetcher) Close() error {
	log.Debug("unregistering eBPF objects")

	var errs []error

	for _, l := range m.netkitPrimaryLinks {
		if l == nil {
			continue
		}
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, l := range m.netkitPeerLinks {
		if l == nil {
			continue
		}
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if m.pktDropsTracePoint != nil {
		if err := m.pktDropsTracePoint.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.rttFentryLink != nil {
		if err := m.rttFentryLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.rttKprobeLink != nil {
		if err := m.rttKprobeLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.networkEventsMonitoringLink != nil {
		if err := m.networkEventsMonitoringLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.nfNatManIPLink != nil {
		if err := m.nfNatManIPLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if m.xfrmInputKretProbeLink != nil {
		if err := m.xfrmInputKretProbeLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if m.xfrmInputKProbeLink != nil {
		if err := m.xfrmInputKProbeLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if m.xfrmOutputKretProbeLink != nil {
		if err := m.xfrmOutputKretProbeLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if m.xfrmOutputKProbeLink != nil {
		if err := m.xfrmOutputKProbeLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if m.sslUprobe != nil {
		if err := m.sslUprobe.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if m.sslDataEventsReader != nil {
		if err := m.sslDataEventsReader.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// m.ringbufReader.Read is a blocking operation, so we need to close the ring buffer
	// from another goroutine to avoid the system not being able to exit if there
	// isn't traffic in a given interface
	if m.ringbufReader != nil {
		if err := m.ringbufReader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.objects != nil {
		if err := m.objects.TcEgressFlowParse.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.TcIngressFlowParse.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.TcxEgressFlowParse.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.TcxIngressFlowParse.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.AggregatedFlows.Unpin(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.AggregatedFlows.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.AggregatedFlowsDns.Unpin(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.AggregatedFlowsDns.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.AggregatedFlowsPktDrop.Unpin(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.AggregatedFlowsPktDrop.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.AggregatedFlowsNetworkEvents.Unpin(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.AggregatedFlowsNetworkEvents.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.AggregatedFlowsXlat.Unpin(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.AggregatedFlowsXlat.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.AdditionalFlowMetrics.Unpin(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.AdditionalFlowMetrics.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.DirectFlows.Unpin(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.DirectFlows.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.DnsFlows.Unpin(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.DnsFlows.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.GlobalCounters.Unpin(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.GlobalCounters.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.FilterMap.Unpin(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.FilterMap.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.PeerFilterMap.Unpin(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.PeerFilterMap.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.IpsecIngressMap.Unpin(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.IpsecIngressMap.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.IpsecEgressMap.Unpin(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.IpsecEgressMap.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.SslDataEventMap.Unpin(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.SslDataEventMap.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.DnsNameMap.Unpin(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.DnsNameMap.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.QuicFlows.Unpin(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.QuicFlows.Close(); err != nil {
			errs = append(errs, err)
		}
		if len(errs) == 0 {
			m.objects = nil
		}
	}

	for iface, ef := range m.egressFilters {
		log := log.WithField("interface", iface)
		log.Debug("deleting egress filter")
		if err := netattach.DoIgnoreNoDev(netlink.FilterDel, netlink.Filter(ef), log); err != nil {
			errs = append(errs, fmt.Errorf("deleting egress filter: %w", err))
		}
	}
	m.egressFilters = map[ifaces.InterfaceKey]*netlink.BpfFilter{}
	for iface, igf := range m.ingressFilters {
		log := log.WithField("interface", iface)
		log.Debug("deleting ingress filter")
		if err := netattach.DoIgnoreNoDev(netlink.FilterDel, netlink.Filter(igf), log); err != nil {
			errs = append(errs, fmt.Errorf("deleting ingress filter: %w", err))
		}
	}
	m.ingressFilters = map[ifaces.InterfaceKey]*netlink.BpfFilter{}
	for iface, qd := range m.qdiscs {
		log := log.WithField("interface", iface)
		log.Debug("deleting Qdisc")
		if err := netattach.DoIgnoreNoDev(netlink.QdiscDel, netlink.Qdisc(qd), log); err != nil {
			errs = append(errs, fmt.Errorf("deleting qdisc: %w", err))
		}
	}
	m.qdiscs = map[ifaces.InterfaceKey]*netlink.GenericQdisc{}

	for iface, l := range m.egressTCXLink {
		log := log.WithField("interface", iface)
		log.Debug("detach egress TCX hook")
		l.Close()
	}
	m.egressTCXLink = map[ifaces.InterfaceKey]link.Link{}
	for iface, l := range m.ingressTCXLink {
		log := log.WithField("interface", iface)
		log.Debug("detach ingress TCX hook")
		l.Close()
	}
	m.ingressTCXLink = map[ifaces.InterfaceKey]link.Link{}

	if err := m.removeAllPins(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) == 0 {
		return nil
	}

	var errStrings []string
	for _, err := range errs {
		errStrings = append(errStrings, err.Error())
	}
	return errors.New(`errors: "` + strings.Join(errStrings, `", "`) + `"`)
}

// removeAllPins removes all pins.
func (m *Fetcher) removeAllPins() error {
	files, err := os.ReadDir(m.pinDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, file := range files {
		if err := os.Remove(path.Join(m.pinDir, file.Name())); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Remove(m.pinDir); err != nil {
		return err
	}
	return nil
}

// doIgnoreNoDev runs the provided syscall over the provided device and ignores the error
// if the cause is a non-existing device (just logs the error as debug).
// If the agent is deployed as part of the Network Observability pipeline, normally
// undeploying the FlowCollector could cause the agent to try to remove resources
// from Pods that have been removed immediately before (e.g. flowlogs-pipeline or the
// console plugin), so we avoid logging some errors that would unnecessarily raise the
// user's attention.
// This function uses generics because the set of provided functions accept different argument
// types.

func (m *Fetcher) ReadRingBuf() (ringbuf.Record, error) {
	return m.ringbufReader.Read()
}

func (m *Fetcher) ReadSSLRingBuf() (ringbuf.Record, error) {
	return m.sslDataEventsReader.Read()
}

// LookupAndDeleteMap reads all the entries from the eBPF map and removes them from it.
// TODO: detect whether BatchLookupAndDelete is supported (Kernel>=5.6) and use it selectively
// Supported Lookup/Delete operations by kernel: https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
func (m *Fetcher) LookupAndDeleteMap(met *metrics.Metrics) map[ebpf.BpfFlowId]model.BpfFlowContent {
	if !m.lookupAndDeleteSupported {
		return m.legacyLookupAndDeleteMap(met)
	}

	flows, ok := m.lookupAndDeleteAggregatedFlows(met)
	if !ok {
		return m.legacyLookupAndDeleteMap(met)
	}

	m.accumulateSecondaryMaps(flows, met)
	m.ReadGlobalCounter(met)
	return flows
}

// lookupAndDeleteAggregatedFlows atomically reads and deletes entries from AggregatedFlows.
// Returns ok=false when the kernel does not support LookupAndDelete (caller should use legacy path).
func (m *Fetcher) lookupAndDeleteAggregatedFlows(met *metrics.Metrics) (map[ebpf.BpfFlowId]model.BpfFlowContent, bool) {
	flowMap := m.objects.AggregatedFlows
	flows := make(map[ebpf.BpfFlowId]model.BpfFlowContent, m.config.CacheMaxFlows)
	var ids []ebpf.BpfFlowId
	var id ebpf.BpfFlowId
	var baseMetrics ebpf.BpfFlowMetrics

	// First, get all ids and don't care about metrics (we need lookup+delete to be atomic)
	iterator := flowMap.Iterate()
	for iterator.Next(&id, &baseMetrics) {
		ids = append(ids, id)
	}

	countMain := 0
	// Run the atomic Lookup+Delete; if new ids have been inserted in the meantime, they'll be fetched next time
	for i, id := range ids {
		countMain++
		if err := flowMap.LookupAndDelete(&id, &baseMetrics); err != nil {
			if i == 0 && errors.Is(err, cilium.ErrNotSupported) {
				log.WithError(err).Warnf("switching to legacy mode")
				m.lookupAndDeleteSupported = false
				return nil, false
			}
			log.WithError(err).WithField("flowId", id).Warnf("couldn't lookup/delete flow entry")
			met.Errors.WithErrorName("flow-fetcher", "CannotDeleteFlows", metrics.HighSeverity).Inc()
			continue
		}
		flows[id] = model.NewBpfFlowContent(baseMetrics)
	}
	met.FlowBufferSizeGauge.WithBufferName("flowmap").Set(float64(countMain))
	return flows, true
}

// accumulateSecondaryMaps merges per-CPU / secondary eBPF map metrics into the main flow map.
func (m *Fetcher) accumulateSecondaryMaps(flows map[ebpf.BpfFlowId]model.BpfFlowContent, met *metrics.Metrics) {
	if m.config.Flows.EnableDNSTracking {
		var dns []ebpf.BpfDnsMetrics
		countDNS := lookupAndDeletePerCPUMap(flows, &dns, m.objects.AggregatedFlowsDns, met, func(flow *model.BpfFlowContent) {
			for i := range dns {
				flow.AccumulateDNS(&dns[i])
			}
		})
		met.FlowBufferSizeGauge.WithBufferName("dnsmap").Set(float64(countDNS))
	}
	if m.config.Flows.EnablePktDrops {
		var pktDrops []ebpf.BpfPktDropMetrics
		countDrops := lookupAndDeletePerCPUMap(flows, &pktDrops, m.objects.AggregatedFlowsPktDrop, met, func(flow *model.BpfFlowContent) {
			for i := range pktDrops {
				flow.AccumulateDrops(&pktDrops[i])
			}
		})
		met.FlowBufferSizeGauge.WithBufferName("pktdropsmap").Set(float64(countDrops))
	}
	if m.config.Flows.EnableNetworkEventsMonitoring {
		var netev []ebpf.BpfNetworkEventsMetrics
		countNetEv := lookupAndDeletePerCPUMap(flows, &netev, m.objects.AggregatedFlowsNetworkEvents, met, func(flow *model.BpfFlowContent) {
			for i := range netev {
				flow.AccumulateNetworkEvents(&netev[i])
			}
		})
		met.FlowBufferSizeGauge.WithBufferName("networkeventsmap").Set(float64(countNetEv))
	}
	if m.config.Flows.EnablePktTranslationTracking {
		var xlat []ebpf.BpfXlatMetrics
		countXlat := lookupAndDeletePerCPUMap(flows, &xlat, m.objects.AggregatedFlowsXlat, met, func(flow *model.BpfFlowContent) {
			for i := range xlat {
				flow.AccumulateXlat(&xlat[i])
			}
		})
		met.FlowBufferSizeGauge.WithBufferName("xlatmap").Set(float64(countXlat))
	}
	if m.config.Flows.EnableRTT || m.config.Flows.EnableIPsecTracking {
		var addit []ebpf.BpfAdditionalMetrics
		countAddit := lookupAndDeletePerCPUMap(flows, &addit, m.objects.AdditionalFlowMetrics, met, func(flow *model.BpfFlowContent) {
			for i := range addit {
				flow.AccumulateAdditional(&addit[i])
			}
		})
		met.FlowBufferSizeGauge.WithBufferName("additionalmap").Set(float64(countAddit))
		if m.config.Flows.EnableIPsecTracking {
			// Correlate IPsec partials (inner xfrm 5-tuple) with on-wire ESP/NAT-T flows.
			mergeIPsecOrphans(flows)
		}
	}
	if m.config.Flows.QUICTrackingMode != 0 {
		var quic []ebpf.BpfQuicMetrics
		countQuic := lookupAndDeletePerCPUMap(flows, &quic, m.objects.QuicFlows, met, func(flow *model.BpfFlowContent) {
			for i := range quic {
				flow.AccumulateQuic(&quic[i])
			}
		})
		met.FlowBufferSizeGauge.WithBufferName("quicmap").Set(float64(countQuic))
	}
	met.FlowBufferSizeGauge.WithBufferName("merged-maps").Set(float64(len(flows)))
}

func lookupAndDeletePerCPUMap(
	flows map[ebpf.BpfFlowId]model.BpfFlowContent,
	perCPUReceiver any,
	bpfMap *cilium.Map,
	met *metrics.Metrics,
	accumulator func(flow *model.BpfFlowContent),
) int {
	var id ebpf.BpfFlowId
	ids := []ebpf.BpfFlowId{}

	it := bpfMap.Iterate()
	for it.Next(&id, perCPUReceiver) {
		ids = append(ids, id)
	}
	for _, id := range ids {
		if err := bpfMap.LookupAndDelete(&id, perCPUReceiver); err != nil {
			log.WithError(err).WithField("flowId", id).Warnf("couldn't lookup/delete secondary map entry")
			met.Errors.WithErrorName("flow-fetcher", "CannotDeleteSecondaryMetric", metrics.HighSeverity).Inc()
			continue
		}
		flow, found := flows[id]
		if !found {
			flow = model.BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{}}
		}
		accumulator(&flow)
		flows[id] = flow
	}
	return len(ids)
}

// ReadGlobalCounter reads the global counter and updates drop flows counter metrics
func (m *Fetcher) ReadGlobalCounter(met *metrics.Metrics) {
	var allCPUValue []uint32
	globalCounters := map[ebpf.BpfGlobalCountersKeyT]prometheus.Counter{
		ebpf.BpfGlobalCountersKeyTHASHMAP_FAIL_CREATE_FLOW:            met.DroppedFlowsCounter.WithSourceAndReason("flow-fetcher", "CannotCreateFlowsHashMap"),
		ebpf.BpfGlobalCountersKeyTHASHMAP_FAIL_UPDATE_FLOW:            met.DroppedFlowsCounter.WithSourceAndReason("flow-fetcher", "CannotUpdateFlowsHashMap"),
		ebpf.BpfGlobalCountersKeyTHASHMAP_FAIL_UPDATE_DNS:             met.DroppedFlowsCounter.WithSourceAndReason("flow-fetcher", "CannotUpdateDNSHashMap"),
		ebpf.BpfGlobalCountersKeyTFILTER_REJECT:                       met.FilteredFlowsCounter.WithSourceAndReason("flow-filtering", "FilterReject"),
		ebpf.BpfGlobalCountersKeyTFILTER_ACCEPT:                       met.FilteredFlowsCounter.WithSourceAndReason("flow-filtering", "FilterAccept"),
		ebpf.BpfGlobalCountersKeyTFILTER_NOMATCH:                      met.FilteredFlowsCounter.WithSourceAndReason("flow-filtering", "FilterNoMatch"),
		ebpf.BpfGlobalCountersKeyTNETWORK_EVENTS_ERR:                  met.NetworkEventsCounter.WithSourceAndReason("network-events", "NetworkEventsErrors"),
		ebpf.BpfGlobalCountersKeyTNETWORK_EVENTS_ERR_GROUPID_MISMATCH: met.NetworkEventsCounter.WithSourceAndReason("network-events", "NetworkEventsErrorsGroupIDMismatch"),
		ebpf.BpfGlobalCountersKeyTNETWORK_EVENTS_ERR_UPDATE_MAP_FLOWS: met.NetworkEventsCounter.WithSourceAndReason("network-events", "NetworkEventsErrorsFlowMapUpdate"),
		ebpf.BpfGlobalCountersKeyTNETWORK_EVENTS_GOOD:                 met.NetworkEventsCounter.WithSourceAndReason("network-events", "NetworkEventsGoodEvent"),
		ebpf.BpfGlobalCountersKeyTOBSERVED_INTF_MISSED:                met.Errors.WithErrorName("flow-fetcher", "MaxObservedInterfacesReached", metrics.LowSeverity),
		ebpf.BpfGlobalCountersKeyTNETWORK_EVENTS_OVERFLOW:             met.Errors.WithErrorName("network-events", "EventsOverflow", metrics.MediumSeverity),
		ebpf.BpfGlobalCountersKeyTNETWORK_EVENTS_COOKIE_TOO_BIG:       met.Errors.WithErrorName("network-events", "CookieTooBig", metrics.MediumSeverity),
	}
	zeroCounters := make([]uint32, cilium.MustPossibleCPU())
	for key := ebpf.BpfGlobalCountersKeyT(0); key < ebpf.BpfGlobalCountersKeyTMAX_COUNTERS; key++ {
		if err := m.objects.GlobalCounters.Lookup(key, &allCPUValue); err != nil {
			log.WithError(err).Warnf("couldn't read global counter")
			return
		}
		metric := globalCounters[key]
		if metric != nil {
			// aggregate all the counters
			for _, counter := range allCPUValue {
				metric.Add(float64(counter))
			}
		}
		// reset the global counter-map entry
		if err := m.objects.GlobalCounters.Put(key, zeroCounters); err != nil {
			log.WithError(err).Warnf("coudn't reset global counter")
			return
		}
	}
}

// DeleteMapsStaleEntries Look for any stale entries in the features maps and delete them
func (m *Fetcher) DeleteMapsStaleEntries(timeOut time.Duration) {
	m.lookupAndDeleteDNSMap(timeOut)
}

// lookupAndDeleteDNSMap iterate over DNS queries map and delete any stale DNS requests
// entries which never get responses for.
func (m *Fetcher) lookupAndDeleteDNSMap(timeOut time.Duration) {
	monotonicTimeNow := monotime.Now()
	dnsMap := m.objects.DnsFlows
	var dnsKey ebpf.BpfDnsFlowId
	var keysToDelete []ebpf.BpfDnsFlowId
	var dnsVal uint64

	if dnsMap != nil {
		// Ideally the Lookup + Delete should be atomic, however we cannot use LookupAndDelete since the deletion is conditional
		// Do not delete while iterating, as it causes severe performance degradation
		iterator := dnsMap.Iterate()
		for iterator.Next(&dnsKey, &dnsVal) {
			if time.Duration(uint64(monotonicTimeNow)-dnsVal) >= timeOut {
				keysToDelete = append(keysToDelete, dnsKey)
			}
		}
		for _, dnsKey = range keysToDelete {
			if err := dnsMap.Delete(dnsKey); err != nil {
				log.WithError(err).WithField("dnsKey", dnsKey).Warnf("couldn't delete DNS record entry")
			}
		}
	}
}

func deletePrograms(spec *cilium.CollectionSpec, programNames ...string) {
	for _, name := range programNames {
		delete(spec.Programs, name)
	}
}

func loadAndAssignPinned(spec *cilium.CollectionSpec, pinDir string, into interface{}) error {
	if err := spec.LoadAndAssign(into, &cilium.CollectionOptions{Maps: cilium.MapOptions{PinPath: pinDir}}); err != nil {
		var ve *cilium.VerifierError
		if errors.As(err, &ve) {
			log.Infof("Verifier error: %+v", ve)
		}
		return fmt.Errorf("loading and assigning BPF objects: %w", err)
	}
	return nil
}

func makeBpfObjects(programs *ebpf.BpfPrograms, maps *ebpf.BpfMaps) ebpf.BpfObjects {
	return ebpf.BpfObjects{
		BpfPrograms: *programs,
		BpfMaps:     *maps,
	}
}

func loadObjectsOldKernelRtKernel(spec *cilium.CollectionSpec, pinDir string) (ebpf.BpfObjects, error) {
	type newBpfPrograms struct {
		TcEgressFlowParse      *cilium.Program `ebpf:"tc_egress_flow_parse"`
		TcIngressFlowParse     *cilium.Program `ebpf:"tc_ingress_flow_parse"`
		NetkitPrimaryFlowParse *cilium.Program `ebpf:"netkit_primary_flow_parse"`
		NetkitPeerFlowParse    *cilium.Program `ebpf:"netkit_peer_flow_parse"`
		TcxEgressFlowParse     *cilium.Program `ebpf:"tcx_egress_flow_parse"`
		TcxIngressFlowParse    *cilium.Program `ebpf:"tcx_ingress_flow_parse"`
		TrackNatManipPkt       *cilium.Program `ebpf:"track_nat_manip_pkt"`
		XfrmInputKretprobe     *cilium.Program `ebpf:"xfrm_input_kretprobe"`
		XfrmOutputKretprobe    *cilium.Program `ebpf:"xfrm_output_kretprobe"`
		XfrmInputKprobe        *cilium.Program `ebpf:"xfrm_input_kprobe"`
		XfrmOutputKprobe       *cilium.Program `ebpf:"xfrm_output_kprobe"`
		ProbeEntrySSLWrite     *cilium.Program `ebpf:"probe_entry_SSL_write"`
	}
	type newBpfObjects struct {
		newBpfPrograms
		ebpf.BpfMaps
	}

	deletePrograms(spec, ebpf.BpfProgKfreeSkb, netattach.NetworkEventsMonitoringHook, ebpf.BpfProgTcpRcvKprobe, ebpf.BpfProgTcpRcvFentry)

	var newObjects newBpfObjects
	if err := loadAndAssignPinned(spec, pinDir, &newObjects); err != nil {
		return ebpf.BpfObjects{}, err
	}

	return makeBpfObjects(
		&ebpf.BpfPrograms{
			TcEgressFlowParse:       newObjects.TcEgressFlowParse,
			TcIngressFlowParse:      newObjects.TcIngressFlowParse,
			NetkitPrimaryFlowParse:  nil,
			NetkitPeerFlowParse:     nil,
			TcxEgressFlowParse:      newObjects.TcxEgressFlowParse,
			TcxIngressFlowParse:     newObjects.TcxIngressFlowParse,
			TrackNatManipPkt:        newObjects.TrackNatManipPkt,
			XfrmInputKretprobe:      newObjects.XfrmInputKretprobe,
			XfrmOutputKretprobe:     newObjects.XfrmOutputKretprobe,
			XfrmInputKprobe:         newObjects.XfrmInputKprobe,
			XfrmOutputKprobe:        newObjects.XfrmOutputKprobe,
			TcpRcvKprobe:            nil,
			TcpRcvFentry:            nil,
			KfreeSkb:                nil,
			NetworkEventsMonitoring: nil,
			ProbeEntrySSL_write:     newObjects.ProbeEntrySSLWrite,
		},
		&newObjects.BpfMaps,
	), nil
}

func loadObjectsOldKernel(spec *cilium.CollectionSpec, pinDir string) (ebpf.BpfObjects, error) {
	type newBpfPrograms struct {
		TcEgressFlowParse      *cilium.Program `ebpf:"tc_egress_flow_parse"`
		TcIngressFlowParse     *cilium.Program `ebpf:"tc_ingress_flow_parse"`
		NetkitPrimaryFlowParse *cilium.Program `ebpf:"netkit_primary_flow_parse"`
		NetkitPeerFlowParse    *cilium.Program `ebpf:"netkit_peer_flow_parse"`
		TcxEgressFlowParse     *cilium.Program `ebpf:"tcx_egress_flow_parse"`
		TcxIngressFlowParse    *cilium.Program `ebpf:"tcx_ingress_flow_parse"`
		TCPRcvKprobe           *cilium.Program `ebpf:"tcp_rcv_kprobe"`
		TrackNatManipPkt       *cilium.Program `ebpf:"track_nat_manip_pkt"`
		XfrmInputKretprobe     *cilium.Program `ebpf:"xfrm_input_kretprobe"`
		XfrmOutputKretprobe    *cilium.Program `ebpf:"xfrm_output_kretprobe"`
		XfrmInputKprobe        *cilium.Program `ebpf:"xfrm_input_kprobe"`
		XfrmOutputKprobe       *cilium.Program `ebpf:"xfrm_output_kprobe"`
		ProbeEntrySSLWrite     *cilium.Program `ebpf:"probe_entry_SSL_write"`
	}
	type newBpfObjects struct {
		newBpfPrograms
		ebpf.BpfMaps
	}

	deletePrograms(spec, ebpf.BpfProgKfreeSkb, netattach.NetworkEventsMonitoringHook, ebpf.BpfProgTcpRcvFentry)

	var newObjects newBpfObjects
	if err := loadAndAssignPinned(spec, pinDir, &newObjects); err != nil {
		return ebpf.BpfObjects{}, err
	}

	return makeBpfObjects(
		&ebpf.BpfPrograms{
			TcEgressFlowParse:       newObjects.TcEgressFlowParse,
			TcIngressFlowParse:      newObjects.TcIngressFlowParse,
			NetkitPrimaryFlowParse:  nil,
			NetkitPeerFlowParse:     nil,
			TcxEgressFlowParse:      newObjects.TcxEgressFlowParse,
			TcxIngressFlowParse:     newObjects.TcxIngressFlowParse,
			TcpRcvKprobe:            newObjects.TCPRcvKprobe,
			TrackNatManipPkt:        newObjects.TrackNatManipPkt,
			XfrmInputKretprobe:      newObjects.XfrmInputKretprobe,
			XfrmOutputKretprobe:     newObjects.XfrmOutputKretprobe,
			XfrmInputKprobe:         newObjects.XfrmInputKprobe,
			XfrmOutputKprobe:        newObjects.XfrmOutputKprobe,
			TcpRcvFentry:            nil,
			KfreeSkb:                nil,
			NetworkEventsMonitoring: nil,
			ProbeEntrySSL_write:     newObjects.ProbeEntrySSLWrite,
		},
		&newObjects.BpfMaps,
	), nil
}

func loadObjectsRtKernel(spec *cilium.CollectionSpec, pinDir string) (ebpf.BpfObjects, error) {
	type newBpfPrograms struct {
		TcEgressFlowParse      *cilium.Program `ebpf:"tc_egress_flow_parse"`
		TcIngressFlowParse     *cilium.Program `ebpf:"tc_ingress_flow_parse"`
		NetkitPrimaryFlowParse *cilium.Program `ebpf:"netkit_primary_flow_parse"`
		NetkitPeerFlowParse    *cilium.Program `ebpf:"netkit_peer_flow_parse"`
		TcxEgressFlowParse     *cilium.Program `ebpf:"tcx_egress_flow_parse"`
		TcxIngressFlowParse    *cilium.Program `ebpf:"tcx_ingress_flow_parse"`
		TCPRcvFentry           *cilium.Program `ebpf:"tcp_rcv_fentry"`
		TrackNatManipPkt       *cilium.Program `ebpf:"track_nat_manip_pkt"`
		XfrmInputKretprobe     *cilium.Program `ebpf:"xfrm_input_kretprobe"`
		XfrmOutputKretprobe    *cilium.Program `ebpf:"xfrm_output_kretprobe"`
		XfrmInputKprobe        *cilium.Program `ebpf:"xfrm_input_kprobe"`
		XfrmOutputKprobe       *cilium.Program `ebpf:"xfrm_output_kprobe"`
		ProbeEntrySSLWrite     *cilium.Program `ebpf:"probe_entry_SSL_write"`
	}
	type newBpfObjects struct {
		newBpfPrograms
		ebpf.BpfMaps
	}

	deletePrograms(spec, ebpf.BpfProgKfreeSkb, netattach.NetworkEventsMonitoringHook, ebpf.BpfProgTcpRcvKprobe)

	var newObjects newBpfObjects
	if err := loadAndAssignPinned(spec, pinDir, &newObjects); err != nil {
		return ebpf.BpfObjects{}, err
	}

	return makeBpfObjects(
		&ebpf.BpfPrograms{
			TcEgressFlowParse:       newObjects.TcEgressFlowParse,
			TcIngressFlowParse:      newObjects.TcIngressFlowParse,
			NetkitPrimaryFlowParse:  nil,
			NetkitPeerFlowParse:     nil,
			TcxEgressFlowParse:      newObjects.TcxEgressFlowParse,
			TcxIngressFlowParse:     newObjects.TcxIngressFlowParse,
			TcpRcvFentry:            newObjects.TCPRcvFentry,
			TrackNatManipPkt:        newObjects.TrackNatManipPkt,
			XfrmInputKretprobe:      newObjects.XfrmInputKretprobe,
			XfrmOutputKretprobe:     newObjects.XfrmOutputKretprobe,
			XfrmInputKprobe:         newObjects.XfrmInputKprobe,
			XfrmOutputKprobe:        newObjects.XfrmOutputKprobe,
			TcpRcvKprobe:            nil,
			KfreeSkb:                nil,
			NetworkEventsMonitoring: nil,
			ProbeEntrySSL_write:     newObjects.ProbeEntrySSLWrite,
		},
		&newObjects.BpfMaps,
	), nil
}

func loadObjectsNoNetworkEvents(spec *cilium.CollectionSpec, pinDir string) (ebpf.BpfObjects, error) {
	type newBpfPrograms struct {
		TcEgressFlowParse      *cilium.Program `ebpf:"tc_egress_flow_parse"`
		TcIngressFlowParse     *cilium.Program `ebpf:"tc_ingress_flow_parse"`
		NetkitPrimaryFlowParse *cilium.Program `ebpf:"netkit_primary_flow_parse"`
		NetkitPeerFlowParse    *cilium.Program `ebpf:"netkit_peer_flow_parse"`
		TcxEgressFlowParse     *cilium.Program `ebpf:"tcx_egress_flow_parse"`
		TcxIngressFlowParse    *cilium.Program `ebpf:"tcx_ingress_flow_parse"`
		TCPRcvFentry           *cilium.Program `ebpf:"tcp_rcv_fentry"`
		TCPRcvKprobe           *cilium.Program `ebpf:"tcp_rcv_kprobe"`
		KfreeSkb               *cilium.Program `ebpf:"kfree_skb"`
		TrackNatManipPkt       *cilium.Program `ebpf:"track_nat_manip_pkt"`
		XfrmInputKretprobe     *cilium.Program `ebpf:"xfrm_input_kretprobe"`
		XfrmOutputKretprobe    *cilium.Program `ebpf:"xfrm_output_kretprobe"`
		XfrmInputKprobe        *cilium.Program `ebpf:"xfrm_input_kprobe"`
		XfrmOutputKprobe       *cilium.Program `ebpf:"xfrm_output_kprobe"`
		ProbeEntrySSLWrite     *cilium.Program `ebpf:"probe_entry_SSL_write"`
	}
	type newBpfObjects struct {
		newBpfPrograms
		ebpf.BpfMaps
	}

	var newObjects newBpfObjects
	if err := loadAndAssignPinned(spec, pinDir, &newObjects); err != nil {
		return ebpf.BpfObjects{}, err
	}

	return makeBpfObjects(
		&ebpf.BpfPrograms{
			TcEgressFlowParse:       newObjects.TcEgressFlowParse,
			TcIngressFlowParse:      newObjects.TcIngressFlowParse,
			NetkitPrimaryFlowParse:  nil,
			NetkitPeerFlowParse:     nil,
			TcxEgressFlowParse:      newObjects.TcxEgressFlowParse,
			TcxIngressFlowParse:     newObjects.TcxIngressFlowParse,
			TcpRcvFentry:            newObjects.TCPRcvFentry,
			TcpRcvKprobe:            newObjects.TCPRcvKprobe,
			KfreeSkb:                newObjects.KfreeSkb,
			TrackNatManipPkt:        newObjects.TrackNatManipPkt,
			XfrmInputKretprobe:      newObjects.XfrmInputKretprobe,
			XfrmOutputKretprobe:     newObjects.XfrmOutputKretprobe,
			XfrmInputKprobe:         newObjects.XfrmInputKprobe,
			XfrmOutputKprobe:        newObjects.XfrmOutputKprobe,
			NetworkEventsMonitoring: nil,
			ProbeEntrySSL_write:     newObjects.ProbeEntrySSLWrite,
		},
		&newObjects.BpfMaps,
	), nil
}

func loadObjectsWithNetkit(spec *cilium.CollectionSpec, pinDir string) (ebpf.BpfObjects, error) {
	type newBpfPrograms struct {
		TcEgressFlowParse       *cilium.Program `ebpf:"tc_egress_flow_parse"`
		TcIngressFlowParse      *cilium.Program `ebpf:"tc_ingress_flow_parse"`
		NetkitPrimaryFlowParse  *cilium.Program `ebpf:"netkit_primary_flow_parse"`
		NetkitPeerFlowParse     *cilium.Program `ebpf:"netkit_peer_flow_parse"`
		TcxEgressFlowParse      *cilium.Program `ebpf:"tcx_egress_flow_parse"`
		TcxIngressFlowParse     *cilium.Program `ebpf:"tcx_ingress_flow_parse"`
		TCPRcvFentry            *cilium.Program `ebpf:"tcp_rcv_fentry"`
		TCPRcvKprobe            *cilium.Program `ebpf:"tcp_rcv_kprobe"`
		KfreeSkb                *cilium.Program `ebpf:"kfree_skb"`
		TrackNatManipPkt        *cilium.Program `ebpf:"track_nat_manip_pkt"`
		XfrmInputKretprobe      *cilium.Program `ebpf:"xfrm_input_kretprobe"`
		XfrmOutputKretprobe     *cilium.Program `ebpf:"xfrm_output_kretprobe"`
		XfrmInputKprobe         *cilium.Program `ebpf:"xfrm_input_kprobe"`
		XfrmOutputKprobe        *cilium.Program `ebpf:"xfrm_output_kprobe"`
		ProbeEntrySSLWrite      *cilium.Program `ebpf:"probe_entry_SSL_write"`
		NetworkEventsMonitoring *cilium.Program `ebpf:"network_events_monitoring"`
	}
	type newBpfObjects struct {
		newBpfPrograms
		ebpf.BpfMaps
	}

	var newObjects newBpfObjects
	if err := loadAndAssignPinned(spec, pinDir, &newObjects); err != nil {
		return ebpf.BpfObjects{}, err
	}

	return makeBpfObjects(
		&ebpf.BpfPrograms{
			TcEgressFlowParse:       newObjects.TcEgressFlowParse,
			TcIngressFlowParse:      newObjects.TcIngressFlowParse,
			NetkitPrimaryFlowParse:  newObjects.NetkitPrimaryFlowParse,
			NetkitPeerFlowParse:     newObjects.NetkitPeerFlowParse,
			TcxEgressFlowParse:      newObjects.TcxEgressFlowParse,
			TcxIngressFlowParse:     newObjects.TcxIngressFlowParse,
			TcpRcvFentry:            newObjects.TCPRcvFentry,
			TcpRcvKprobe:            newObjects.TCPRcvKprobe,
			KfreeSkb:                newObjects.KfreeSkb,
			TrackNatManipPkt:        newObjects.TrackNatManipPkt,
			XfrmInputKretprobe:      newObjects.XfrmInputKretprobe,
			XfrmOutputKretprobe:     newObjects.XfrmOutputKretprobe,
			XfrmInputKprobe:         newObjects.XfrmInputKprobe,
			XfrmOutputKprobe:        newObjects.XfrmOutputKprobe,
			NetworkEventsMonitoring: newObjects.NetworkEventsMonitoring,
			ProbeEntrySSL_write:     newObjects.ProbeEntrySSLWrite,
		},
		&newObjects.BpfMaps,
	), nil
}

// kernelSpecificLoadAndAssign based on a kernel version, it will load only the supported eBPF hooks
func kernelSpecificLoadAndAssign(oldKernel, rtKernel, supportNetworkEvents bool, supportNetkit bool, spec *cilium.CollectionSpec, pinDir string) (ebpf.BpfObjects, error) {
	var (
		objects ebpf.BpfObjects
		err     error
	)

	switch {
	case oldKernel && rtKernel:
		objects, err = loadObjectsOldKernelRtKernel(spec, pinDir)
	case oldKernel:
		objects, err = loadObjectsOldKernel(spec, pinDir)
	case rtKernel:
		objects, err = loadObjectsRtKernel(spec, pinDir)
	case !supportNetworkEvents:
		objects, err = loadObjectsNoNetworkEvents(spec, pinDir)
	case supportNetkit:
		objects, err = loadObjectsWithNetkit(spec, pinDir)
	default:
		if err = loadAndAssignPinned(spec, pinDir, &objects); err != nil {
			break
		}
	}
	if err != nil {
		return ebpf.BpfObjects{}, err
	}

	return objects, nil
}
func configureFlowSpecVariables(spec *cilium.CollectionSpec, cfg *tracer.FetcherConfig, filter *attach.Filter) error {
	traceMsgs := 0
	if cfg.Debug {
		traceMsgs = 1
	}
	enableRtt := 0
	if cfg.Flows.EnableRTT {
		enableRtt = 1
	}
	enableDNSTracking := 0
	dnsTrackerPort := uint16(netattach.DNSDefaultPort)
	if cfg.Flows.EnableDNSTracking {
		enableDNSTracking = 1
		if cfg.Flows.DNSTrackingPort != 0 {
			dnsTrackerPort = cfg.Flows.DNSTrackingPort
		}
	}
	if enableDNSTracking == 0 {
		spec.Maps[ebpf.BpfMapDnsFlows].MaxEntries = 1
	}
	enableFlowFiltering := 0
	hasFilterSampling := uint8(0)
	if filter != nil {
		enableFlowFiltering = 1
		hasFilterSampling = filter.HasSampling()
	} else {
		spec.Maps[ebpf.BpfMapFilterMap].MaxEntries = 1
		spec.Maps[ebpf.BpfMapPeerFilterMap].MaxEntries = 1
	}
	enableNetworkEventsMonitoring := 0
	if cfg.Flows.EnableNetworkEventsMonitoring {
		enableNetworkEventsMonitoring = 1
	}
	networkEventsMonitoringGroupID := netattach.DefaultNetworkEventsGroupID
	if cfg.Flows.NetworkEventsMonitoringGroupID > 0 {
		networkEventsMonitoringGroupID = cfg.Flows.NetworkEventsMonitoringGroupID
	}
	enablePktTranslation := 0
	if cfg.Flows.EnablePktTranslationTracking {
		enablePktTranslation = 1
	}
	enableIPsec := 0
	if cfg.Flows.EnableIPsecTracking {
		enableIPsec = 1
	}
	if enableIPsec == 0 {
		spec.Maps[ebpf.BpfMapIpsecIngressMap].MaxEntries = 1
		spec.Maps[ebpf.BpfMapIpsecEgressMap].MaxEntries = 1
	}
	enableTLSTracking := 0
	if cfg.Flows.EnableTLSTracking {
		enableTLSTracking = 1
	}

	enableDirectFlowRingbuf := 0
	if cfg.Flows.EnableFlowsRingbufFallback {
		enableDirectFlowRingbuf = 1
	}
	enableOpenSSLTracking := 0
	if cfg.Flows.EnableOpenSSLTracking {
		enableOpenSSLTracking = 1
	}

	// enable_quic_tracking mode:
	// QUIC_CONFIG_DISABLED = 0, QUIC_CONFIG_ENABLED = 1, QUIC_CONFIG_ANY_UDP_PORT = 2.
	enableQUICTracking := ebpf.BpfQuicConfigTQUIC_CONFIG_DISABLED
	switch cfg.Flows.QUICTrackingMode {
	case 2:
		enableQUICTracking = ebpf.BpfQuicConfigTQUIC_CONFIG_ANY_UDP_PORT
	case 1:
		enableQUICTracking = ebpf.BpfQuicConfigTQUIC_CONFIG_ENABLED
	}
	// Flow-only BPF variables; packet fetcher uses pkg/ebpf/packets.
	variables := []netattach.VariableMapping{
		{Key: ebpf.BpfVarSampling, Value: uint32(cfg.Sampling)},
		{Key: ebpf.BpfVarHasFilterSampling, Value: hasFilterSampling},
		{Key: ebpf.BpfVarTraceMessages, Value: uint8(traceMsgs)},
		{Key: ebpf.BpfVarEnableRtt, Value: uint8(enableRtt)},
		{Key: ebpf.BpfVarEnableDnsTracking, Value: uint8(enableDNSTracking)},
		{Key: ebpf.BpfVarDnsPort, Value: dnsTrackerPort},
		{Key: ebpf.BpfVarEnableFiltering, Value: uint8(enableFlowFiltering)},
		{Key: ebpf.BpfVarEnableNetworkEventsMonitoring, Value: uint8(enableNetworkEventsMonitoring)},
		{Key: ebpf.BpfVarNetworkEventsMonitoringGroupid, Value: uint8(networkEventsMonitoringGroupID)},
		{Key: ebpf.BpfVarEnablePktTranslationTracking, Value: uint8(enablePktTranslation)},
		{Key: ebpf.BpfVarEnableIpsec, Value: uint8(enableIPsec)},
		{Key: ebpf.BpfVarEnableDirectflowsRingbuf, Value: uint8(enableDirectFlowRingbuf)},
		{Key: ebpf.BpfVarEnableOpensslTracking, Value: uint8(enableOpenSSLTracking)},
		{Key: ebpf.BpfVarEnableTlsUsageTracking, Value: uint8(enableTLSTracking)},
		{Key: ebpf.BpfVarEnableQuicTracking, Value: uint8(enableQUICTracking)},
	}

	for _, mapping := range variables {
		if err := netattach.SetVariable(spec, mapping.Key, mapping.Value); err != nil {
			return err
		}
	}

	return nil
}

func sizeMapForFeature(spec *cilium.CollectionSpec, name string, enabled bool, size int) {
	if enabled {
		spec.Maps[name].MaxEntries = uint32(size)
	} else {
		spec.Maps[name].MaxEntries = 1
	}
}
