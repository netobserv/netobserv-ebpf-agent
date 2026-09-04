package attach

import "github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"

// Attacher registers eBPF TC/TCX/netkit hooks on network interfaces.
type Attacher interface {
	Register(iface *ifaces.Interface) error
	UnRegister(iface *ifaces.Interface) error
	AttachTCX(iface *ifaces.Interface) error
	DetachTCX(iface *ifaces.Interface) error
}
