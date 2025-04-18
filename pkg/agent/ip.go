package agent

import (
	"fmt"
	"net"
	"strings"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
)

// dependencies that can be injected from testing
var (
	interfaceByName = net.InterfaceByName
	interfaceAddrs  = net.InterfaceAddrs
	dial            = net.Dial
	ifaceAddrs      = func(iface *net.Interface) ([]net.Addr, error) {
		return iface.Addrs()
	}
)

// fetchAgentIP guesses the non-loopback IP address of the Agent host, according to the
// user-provided configuration:
//   - If AgentIP is provided, this value is used whatever is the real IP of the Agent.
//   - AgentIPIface specifies which interface this function should look into in order to pickup an address.
//   - AgentIPType specifies which type of IP address should the agent pickup ("any" to pickup whichever
//     ipv4 or ipv6 address is found first)
func fetchAgentIP(cfg *config.Agent) (net.IP, error) {
	if cfg.AgentIP != "" {
		if ip := net.ParseIP(cfg.AgentIP); ip != nil {
			return ip, nil
		}
		return nil, fmt.Errorf("can't parse provided IP %v", cfg.AgentIP)
	}

	if cfg.AgentIPType != config.IPTypeAny &&
		cfg.AgentIPType != config.IPTypeIPV6 &&
		cfg.AgentIPType != config.IPTypeIPV4 {
		return nil, fmt.Errorf("invalid IP type %q. Valid values are: %s, %s or %s",
			cfg.AgentIPType, config.IPTypeIPV4, config.IPTypeIPV6, config.IPTypeAny)
	}

	switch cfg.AgentIPIface {
	case config.IPIfaceLocal:
		return fromLocal(cfg.AgentIPType)
	case config.IPIfaceExternal:
		return fromExternal(cfg.AgentIPType)
	default:
		if !strings.HasPrefix(cfg.AgentIPIface, config.IPIfaceNamedPrefix) {
			return nil, fmt.Errorf(
				"invalid IP interface %q. Valid values are: %s, %s or %s<iface_name>",
				cfg.AgentIPIface, config.IPIfaceLocal, config.IPIfaceExternal, config.IPIfaceNamedPrefix)
		}
		return fromInterface(cfg.AgentIPIface[len(config.IPIfaceNamedPrefix):], cfg.AgentIPType)
	}
}

func fromInterface(ifName, ipType string) (net.IP, error) {
	iface, err := interfaceByName(ifName)
	if err != nil {
		return nil, err
	}
	addrs, err := ifaceAddrs(iface)
	if err != nil {
		return nil, err
	}
	if ip, ok := findAddress(addrs, ipType); ok {
		return ip, nil
	}
	return nil, fmt.Errorf("no matching %q addresses found at interface %v", ipType, ifName)
}

func fromLocal(ipType string) (net.IP, error) {
	addrs, err := interfaceAddrs()
	if err != nil {
		return nil, err
	}
	if ip, ok := findAddress(addrs, ipType); ok {
		return ip, nil
	}
	return nil, fmt.Errorf("no matching local %q addresses found", ipType)
}

func fromExternal(ipType string) (net.IP, error) {
	// We don't really care about the existence or nonexistence of the addresses.
	// This will just establish an external dialer where we can pickup the external
	// host address
	addrStr := "8.8.8.8:80"
	// When IPType is "any" and we have interface with IPv6 address only then use ipv6 dns address
	ip, _ := fromLocal(config.IPTypeIPV4)
	if ipType == config.IPTypeIPV6 || (ipType == config.IPTypeAny && ip == nil) {
		addrStr = "[2001:4860:4860::8888]:80"
	}
	conn, err := dial("udp", addrStr)
	if err != nil {
		return nil, fmt.Errorf("can't establish an external connection %w", err)
	}
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); !ok {
		return nil, fmt.Errorf("unexpected local address type %T for external connection",
			conn.LocalAddr())
	} else if ip, ok := getIP(addr.IP, ipType); ok {
		return ip, nil
	}
	return nil, fmt.Errorf("no matching %q external addresses found", ipType)
}

func findAddress(addrs []net.Addr, ipType string) (net.IP, bool) {
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet != nil {
			if ip, ok := getIP(ipnet.IP, ipType); ok {
				return ip, true
			}
		}
	}
	return nil, false
}

func getIP(pip net.IP, ipType string) (net.IP, bool) {
	if pip == nil || pip.IsLoopback() || pip.IsLinkLocalUnicast() {
		return nil, false
	}
	switch ipType {
	case config.IPTypeIPV4:
		if ip := pip.To4(); ip != nil {
			return ip, true
		}
	case config.IPTypeIPV6:
		// as any IP4 address can be converted to IP6, we only return any
		// address that can be converted to IP6 but not to IP4
		if ip := pip.To16(); ip != nil && pip.To4() == nil {
			return ip, true
		}
	default: // Any
		if ip := pip.To4(); ip != nil {
			return ip, true
		}
		if ip := pip.To16(); ip != nil {
			return ip, true
		}
	}
	return nil, false
}
