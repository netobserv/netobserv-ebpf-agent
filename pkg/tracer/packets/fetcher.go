package packets

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/packets"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/attach"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/internal/netattach"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/plaintext"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

var plog = logrus.WithField("component", "ebpf.PacketFetcher")

type Fetcher struct {
	objects                  *packets.PacketsObjects
	qdiscs                   map[ifaces.InterfaceKey]*netlink.GenericQdisc
	egressFilters            map[ifaces.InterfaceKey]*netlink.BpfFilter
	ingressFilters           map[ifaces.InterfaceKey]*netlink.BpfFilter
	perfReader               *ringbuf.Reader
	sslDataEventsReader      *ringbuf.Reader
	cacheMaxSize             int
	enableIngress            bool
	enableEgress             bool
	ingressAnchor            link.Anchor
	egressAnchor             link.Anchor
	egressTCXLink            map[ifaces.InterfaceKey]link.Link
	ingressTCXLink           map[ifaces.InterfaceKey]link.Link
	netkitPrimaryLink        map[ifaces.InterfaceKey]link.Link
	netkitPeerLink           map[ifaces.InterfaceKey]link.Link
	opensslAttacher          *plaintext.OpenSSLAttacher
	lookupAndDeleteSupported bool
	config                   *tracer.FetcherConfig
}

func NewFetcher(cfg *tracer.FetcherConfig) (*Fetcher, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		plog.WithError(err).
			Warn("can't remove mem lock. The agent could not be able to start eBPF programs")
	}

	spec, err := packets.LoadPackets()
	if err != nil {
		return nil, err
	}

	enableFiltering := uint8(0)
	if len(cfg.FilterConfig) > 0 {
		enableFiltering = 1
	}
	enableOpenSSLTracking := uint8(0)
	if cfg.EnableOpenSSLTracking {
		enableOpenSSLTracking = 1
	}
	variables := []netattach.VariableMapping{
		{Key: ebpf.BpfVarSampling, Value: uint32(cfg.Sampling)},
		{Key: ebpf.BpfVarEnableFiltering, Value: enableFiltering},
		{Key: ebpf.BpfVarEnableOpensslTracking, Value: enableOpenSSLTracking},
	}
	for _, mapping := range variables {
		if err := netattach.SetVariable(spec, mapping.Key, mapping.Value); err != nil {
			return nil, fmt.Errorf("failed to set variable %s: %w", mapping.Key, err)
		}
	}

	for _, m := range []string{
		"filter_map",
		"peer_filter_map",
		"global_counters",
		"packet_record",
		"ssl_data_event_map",
		"ssl_read_active_map",
		"ssl_fd_map",
	} {
		spec.Maps[m].Pinning = 0
	}

	if !cfg.EnableOpenSSLTracking {
		const ringbufMinSize = 1 << 12
		spec.Maps["ssl_data_event_map"].MaxEntries = ringbufMinSize
	}

	objects := &packets.PacketsObjects{}
	if err := spec.LoadAndAssign(objects, &cilium.CollectionOptions{Maps: cilium.MapOptions{PinPath: ""}}); err != nil {
		var ve *cilium.VerifierError
		if errors.As(err, &ve) {
			plog.Infof("Verifier error: %+v", ve)
		}
		return nil, fmt.Errorf("loading and assigning packet BPF objects: %w", err)
	}

	f := attach.NewFilter(cfg.FilterConfig)
	if err := f.ProgramPacketsFilter(objects); err != nil {
		return nil, fmt.Errorf("programming packet filter: %w", err)
	}

	reader, err := ringbuf.NewReader(objects.PacketRecord)
	if err != nil {
		return nil, fmt.Errorf("accessing packet ringbuf: %w", err)
	}

	var sslReader *ringbuf.Reader
	var opensslAtt *plaintext.OpenSSLAttacher
	if cfg.EnableOpenSSLTracking {
		sslReader, err = ringbuf.NewReader(objects.SslDataEventMap)
		if err != nil {
			return nil, fmt.Errorf("accessing SSL data event ringbuffer: %w", err)
		}

		opensslAtt, err = plaintext.AttachOpenSSLUprobes(
			cfg.PlaintextScope, cfg.OpenSSLPath,
			objects.ProbeEntrySSL_write, objects.ProbeEntrySSL_read,
			objects.ProbeRetSSL_read, objects.ProbeEntrySSL_setFd,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to attach OpenSSL uprobes: %w", err)
		}
		plog.Infof("SSL tracking enabled with dynamic libssl discovery (default: %s)", cfg.OpenSSLPath)
	}

	return &Fetcher{
		objects:                  objects,
		perfReader:               reader,
		sslDataEventsReader:      sslReader,
		opensslAttacher:          opensslAtt,
		egressFilters:            map[ifaces.InterfaceKey]*netlink.BpfFilter{},
		ingressFilters:           map[ifaces.InterfaceKey]*netlink.BpfFilter{},
		qdiscs:                   map[ifaces.InterfaceKey]*netlink.GenericQdisc{},
		cacheMaxSize:             cfg.CacheMaxFlows,
		enableIngress:            cfg.EnableIngress,
		enableEgress:             cfg.EnableEgress,
		egressTCXLink:            map[ifaces.InterfaceKey]link.Link{},
		ingressTCXLink:           map[ifaces.InterfaceKey]link.Link{},
		netkitPrimaryLink:        map[ifaces.InterfaceKey]link.Link{},
		netkitPeerLink:           map[ifaces.InterfaceKey]link.Link{},
		lookupAndDeleteSupported: true,
		config:                   cfg,
	}, nil
}
func (p *Fetcher) UnRegister(iface *ifaces.Interface) error {

	if l := p.netkitPrimaryLink[iface.InterfaceKey]; l != nil {
		_ = l.Close()
	}
	if l := p.netkitPeerLink[iface.InterfaceKey]; l != nil {
		_ = l.Close()
	}
	delete(p.netkitPrimaryLink, iface.InterfaceKey)
	delete(p.netkitPeerLink, iface.InterfaceKey)
	// qdiscs, ingress and egress filters are automatically deleted so we don't need to
	// specifically detach them from the packet fetcher
	return netattach.Unregister(iface, "tc_ingress_packet_parse", "tc_egress_packet_parse", plog)
}

func (p *Fetcher) Register(iface *ifaces.Interface) error {
	qdisc, ipvlan, err := netattach.RegisterInterface(iface, plog)
	if err != nil {
		return err
	}
	if n, ok := ipvlan.(*netlink.Netkit); ok && n.Type() == "netkit" {
		return p.registerNetkit(iface)
	}

	p.qdiscs[iface.InterfaceKey] = qdisc

	if err := p.registerEgress(iface, ipvlan); err != nil {
		return err
	}
	return p.registerIngress(iface, ipvlan)
}

func (p *Fetcher) registerNetkit(iface *ifaces.Interface) error {
	ilog := plog.WithField("iface", iface)
	return netattach.WithNetNS(iface.NetNS, func() error {
		// Attach on primary side (draft mapping: EGRESS).
		if p.enableEgress {
			if p.objects.NetkitPrimaryPacketParse == nil {
				return fmt.Errorf("netkit primary pca program not loaded")
			}
			lnk, err := link.AttachNetkit(link.NetkitOptions{
				Program:   p.objects.NetkitPrimaryPacketParse,
				Attach:    cilium.AttachNetkitPrimary,
				Interface: iface.Index,
			})
			if err != nil {
				if errors.Is(err, fs.ErrExist) {
					ilog.Debug("netkit primary pca link already exists; ignoring")
				} else {
					return fmt.Errorf("failed to attach netkit primary pca: %w", err)
				}
			} else {
				p.netkitPrimaryLink[iface.InterfaceKey] = lnk
			}
		}

		// Attach on peer side (draft mapping: INGRESS).
		if p.enableIngress {
			if p.objects.NetkitPeerPacketParse == nil {
				return fmt.Errorf("netkit peer pca program not loaded")
			}
			lnk, err := link.AttachNetkit(link.NetkitOptions{
				Program:   p.objects.NetkitPeerPacketParse,
				Attach:    cilium.AttachNetkitPeer,
				Interface: iface.Index,
			})
			if err != nil {
				if errors.Is(err, fs.ErrExist) {
					ilog.Debug("netkit peer pca link already exists; ignoring")
				} else {
					return fmt.Errorf("failed to attach netkit peer pca: %w", err)
				}
			} else {
				p.netkitPeerLink[iface.InterfaceKey] = lnk
			}
		}

		return nil
	})
}

func (p *Fetcher) registerEgress(iface *ifaces.Interface, ipvlan netlink.Link) error {
	egressFilter, err := netattach.FetchEgressEvents(iface, ipvlan, p.objects.TcEgressPacketParse, "tc_egress_packet_parse", plog)
	if err != nil {
		return err
	}

	p.egressFilters[iface.InterfaceKey] = egressFilter
	return nil
}

func (p *Fetcher) registerIngress(iface *ifaces.Interface, ipvlan netlink.Link) error {
	ingressFilter, err := netattach.FetchIngressEvents(iface, ipvlan, p.objects.TcIngressPacketParse, "tc_ingress_packet_parse", plog)
	if err != nil {
		return err
	}

	p.ingressFilters[iface.InterfaceKey] = ingressFilter
	return nil
}

// Close the eBPF fetcher from the system.

func (p *Fetcher) DetachTCX(iface *ifaces.Interface) error {
	ilog := plog.WithField("iface", iface)
	var oneErr error

	hasNetkitLink := p.netkitPrimaryLink[iface.InterfaceKey] != nil || p.netkitPeerLink[iface.InterfaceKey] != nil
	if hasNetkitLink {
		if l := p.netkitPrimaryLink[iface.InterfaceKey]; l != nil {
			if err := l.Close(); err != nil {
				oneErr = tracer.NewErrorNoRetry("Detach:CantCloseNetkitPrimaryLink", fmt.Errorf("failed to close netkit primary link: %w", err))
			}
		}
		if l := p.netkitPeerLink[iface.InterfaceKey]; l != nil {
			if err := l.Close(); err != nil {
				oneErr = tracer.NewErrorNoRetry("Detach:CantCloseNetkitPeerLink", fmt.Errorf("failed to close netkit peer link: %w", err))
			}
		}
		delete(p.netkitPrimaryLink, iface.InterfaceKey)
		delete(p.netkitPeerLink, iface.InterfaceKey)
		return oneErr
	}

	if p.enableEgress {
		if l := p.egressTCXLink[iface.InterfaceKey]; l != nil {
			if err := l.Close(); err != nil {
				oneErr = tracer.NewErrorNoRetry("DetachEgress:CantCloseLink", fmt.Errorf("TCX: failed to close egress link: %w", err))
			} else {
				ilog.WithField("interface", iface.Name).Debug("successfully detach egressTCX hook")
			}
		} else {
			oneErr = tracer.NewErrorNoRetry("DetachEgress:TCXNoLink", fmt.Errorf("egress link not found for interface %v", iface.Name))
		}
		delete(p.egressTCXLink, iface.InterfaceKey)
	}

	if p.enableIngress {
		if l := p.ingressTCXLink[iface.InterfaceKey]; l != nil {
			if err := l.Close(); err != nil {
				oneErr = tracer.NewErrorNoRetry("DetachIngress:CantCloseLink", fmt.Errorf("TCX: failed to close ingress link: %w", err))
			} else {
				ilog.WithField("interface", iface.Name).Debug("successfully detach ingressTCX hook")
			}
		} else {
			oneErr = tracer.NewErrorNoRetry("DetachIngress:TCXNoLink", fmt.Errorf("ingress link not found for interface %v", iface.Name))
		}
		delete(p.ingressTCXLink, iface.InterfaceKey)
	}
	return oneErr
}

func (p *Fetcher) AttachTCX(iface *ifaces.Interface) error { //nolint:cyclop // mirrors flow TCX attach error handling
	ilog := plog.WithField("iface", iface)
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
		ilog.Debug("detected netkit interface; attaching via netkit hooks")
		return p.registerNetkit(iface)
	}

	if iface.NetNS != netns.None() {
		originalNs, err := netns.Get()
		if err != nil {
			return tracer.NewError("Attach:CantGetNetNS", fmt.Errorf("PCA failed to get current netns: %w", err))
		}
		defer func() {
			if err := netns.Set(originalNs); err != nil {
				ilog.WithError(err).Error("PCA failed to set netns back")
			}
			originalNs.Close()
		}()
		if err := unix.Setns(int(iface.NetNS), unix.CLONE_NEWNET); err != nil {
			return tracer.NewError("Attach:CantSetNetNS", fmt.Errorf("PCA failed to setns to %s: %w", iface.NetNS, err))
		}
	}

	if p.enableEgress {
		egrLink, err := link.AttachTCX(link.TCXOptions{
			Program:   p.objects.TcxEgressPacketParse,
			Attach:    cilium.AttachTCXEgress,
			Interface: iface.Index,
			Anchor:    p.egressAnchor,
		})
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				// The interface already has a TCX egress hook
				plog.WithField("iface", iface.Name).Debug("interface already has a TCX PCA egress hook ignore")
				if q, err := link.QueryPrograms(link.QueryOptions{
					Target: iface.Index,
					Attach: cilium.AttachTCXEgress,
				}); err == nil {
					for _, id := range q.Programs {
						linkID, ok := id.LinkID()
						if !ok {
							return tracer.NewError("Attach:CantGetLinkID", fmt.Errorf("failed to get linkID for %s: %w", iface.Name, err))
						}
						if egrLink, err = link.NewFromID(linkID); err != nil {
							return tracer.NewError("Attach:CantCreateEgressLinkID", fmt.Errorf("failed to get link for egress flow to %s: %w", iface.Name, err))
						}
						ilog.WithField("link", linkID).Debug("attaching egress flow to link")
					}
				} else {
					return tracer.NewError("Attach:CantQueryTCXEgress", fmt.Errorf("failed to query TCX egress flow to %s: %w", iface.Name, err))
				}
			} else {
				return tracer.NewError("Attach:CantAttachTCXEgress", fmt.Errorf("failed to attach PCA TCX egress: %w", err))
			}
		}
		p.egressTCXLink[iface.InterfaceKey] = egrLink
		ilog.WithField("interface", iface.Name).Debug("successfully attach PCA egressTCX hook")
	}

	if p.enableIngress {
		ingLink, err := link.AttachTCX(link.TCXOptions{
			Program:   p.objects.TcxIngressPacketParse,
			Attach:    cilium.AttachTCXIngress,
			Interface: iface.Index,
			Anchor:    p.ingressAnchor,
		})
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				// The interface already has a TCX ingress hook
				plog.WithField("iface", iface.Name).Debug("interface already has a TCX PCA ingress hook ignore")
				if q, err := link.QueryPrograms(link.QueryOptions{
					Target: iface.Index,
					Attach: cilium.AttachTCXIngress,
				}); err == nil {
					for _, id := range q.Programs {
						linkID, ok := id.LinkID()
						if !ok {
							return tracer.NewError("Attach:CantGetLinkID", fmt.Errorf("failed to get linkID for %s: %w", iface.Name, err))
						}
						if ingLink, err = link.NewFromID(linkID); err != nil {
							return tracer.NewError("Attach:CantCreateIngressLinkID", fmt.Errorf("failed to get link for ingress flow to %s: %w", iface.Name, err))
						}
						ilog.WithField("link", linkID).Debug("attaching ingress flow to link")
					}
				} else {
					return tracer.NewError("Attach:CantQueryTCXIngress", fmt.Errorf("failed to query TCX ingress flow to %s: %w", iface.Name, err))
				}
			} else {
				return tracer.NewError("Attach:CantAttachTCXIngress", fmt.Errorf("failed to attach PCA TCX ingress: %w", err))
			}
		}
		p.ingressTCXLink[iface.InterfaceKey] = ingLink
		ilog.WithField("interface", iface.Name).Debug("successfully attach PCA ingressTCX hook")
	}

	return nil
}

// We don't need an "Close(iface)" method because the filters and qdiscs
// are automatically removed when the interface is down
// nolint:cyclop
func (p *Fetcher) Close() error {
	plog.Debug("unregistering eBPF objects")

	var errs []error
	if p.opensslAttacher != nil {
		p.opensslAttacher.Close()
	}
	if p.sslDataEventsReader != nil {
		if err := p.sslDataEventsReader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if p.perfReader != nil {
		if err := p.perfReader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if p.objects != nil {
		if err := p.objects.TcEgressPacketParse.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := p.objects.TcIngressPacketParse.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := p.objects.TcxEgressPacketParse.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := p.objects.TcxIngressPacketParse.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := p.objects.PacketRecord.Close(); err != nil {
			errs = append(errs, err)
		}
		p.objects = nil
	}
	for iface, ef := range p.egressFilters {
		plog.WithField("interface", iface).Debug("deleting egress filter")
		if err := netlink.FilterDel(ef); err != nil {
			errs = append(errs, fmt.Errorf("deleting egress filter: %w", err))
		}
	}
	p.egressFilters = map[ifaces.InterfaceKey]*netlink.BpfFilter{}
	for iface, igf := range p.ingressFilters {
		plog.WithField("interface", iface).Debug("deleting ingress filter")
		if err := netlink.FilterDel(igf); err != nil {
			errs = append(errs, fmt.Errorf("deleting ingress filter: %w", err))
		}
	}
	p.ingressFilters = map[ifaces.InterfaceKey]*netlink.BpfFilter{}
	for iface, qd := range p.qdiscs {
		plog.WithField("interface", iface).Debug("deleting Qdisc")
		if err := netlink.QdiscDel(qd); err != nil {
			errs = append(errs, fmt.Errorf("deleting qdisc: %w", err))
		}
	}
	p.qdiscs = map[ifaces.InterfaceKey]*netlink.GenericQdisc{}

	for iface, l := range p.egressTCXLink {
		log := plog.WithField("interface", iface)
		log.Debug("detach egress TCX hook")
		l.Close()
	}
	p.egressTCXLink = map[ifaces.InterfaceKey]link.Link{}
	for iface, l := range p.ingressTCXLink {
		log := plog.WithField("interface", iface)
		log.Debug("detach ingress TCX hook")
		l.Close()
	}
	p.ingressTCXLink = map[ifaces.InterfaceKey]link.Link{}

	if len(errs) == 0 {
		return nil
	}

	var errStrings []string
	for _, err := range errs {
		errStrings = append(errStrings, err.Error())
	}
	return errors.New(`errors: "` + strings.Join(errStrings, `", "`) + `"`)
}

func (p *Fetcher) ReadPerf() (ringbuf.Record, error) {
	return p.perfReader.Read()
}

func (p *Fetcher) ReadSSLRingBuf() (ringbuf.Record, error) {
	if p.sslDataEventsReader == nil {
		return ringbuf.Record{}, fmt.Errorf("SSL ring buffer not initialized")
	}
	return p.sslDataEventsReader.Read()
}

func (p *Fetcher) LookupAndDeleteMap(met *metrics.Metrics) map[int][]*byte {
	if !p.lookupAndDeleteSupported {
		return p.legacyLookupAndDeleteMap(met)
	}

	packetMap := p.objects.PacketRecord
	iterator := packetMap.Iterate()
	packets := make(map[int][]*byte, p.cacheMaxSize)
	var id int
	var ids []int
	var packet []*byte

	// First, get all ids and ignore content (we need lookup+delete to be atomic)
	for iterator.Next(&id, &packet) {
		ids = append(ids, id)
	}

	// Run the atomic Lookup+Delete; if new ids have been inserted in the meantime, they'll be fetched next time
	for i, id := range ids {
		if err := packetMap.LookupAndDelete(&id, &packet); err != nil {
			if i == 0 && errors.Is(err, cilium.ErrNotSupported) {
				plog.WithError(err).Warnf("switching to legacy mode")
				p.lookupAndDeleteSupported = false
				return p.legacyLookupAndDeleteMap(met)
			}
			plog.WithError(err).WithField("packetID", id).Warnf("couldn't delete entry")
			met.Errors.WithErrorName("pkt-fetcher", "CannotDeleteEntry", metrics.HighSeverity).Inc()
		}
		packets[id] = packet
	}

	return packets
}
