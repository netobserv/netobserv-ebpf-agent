package agent

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInterfaces_DefaultConfig(t *testing.T) {
	ifaces, err := initRegexpInterfaceFilter(nil, []string{"lo"})
	require.NoError(t, err)

	// Allowed
	for _, iface := range []string{"eth0", "br-0"} {
		allowed, err := ifaces.Allowed(iface)
		require.NoError(t, err)
		assert.True(t, allowed)
	}

	// Not Allowed
	allowed, err := ifaces.Allowed("lo")
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestInterfaceFilter_SelectingInterfaces_DefaultExclusion(t *testing.T) {
	ifaces, err := initRegexpInterfaceFilter([]string{"eth0", "/^br-/"}, []string{"lo"})
	require.NoError(t, err)

	// Allowed
	for _, iface := range []string{"eth0", "br-0"} {
		allowed, err := ifaces.Allowed(iface)
		require.NoError(t, err)
		assert.True(t, allowed)
	}
	// Not Allowed
	for _, iface := range []string{"eth01", "abr-3", "lo"} {
		allowed, err := ifaces.Allowed(iface)
		require.NoError(t, err)
		assert.False(t, allowed)
	}
}

func TestInterfaceFilter_ExclusionTakesPriority(t *testing.T) {
	ifaces, err := initRegexpInterfaceFilter([]string{"/^eth/", "/^br-/"}, []string{"eth1", "/^br-1/"})
	require.NoError(t, err)

	// Allowed
	for _, iface := range []string{"eth0", "eth-10", "eth11", "br-2", "br-0"} {
		allowed, err := ifaces.Allowed(iface)
		require.NoError(t, err)
		assert.True(t, allowed)
	}
	// Not Allowed
	for _, iface := range []string{"eth1", "br-1", "br-10"} {
		allowed, err := ifaces.Allowed(iface)
		require.NoError(t, err)
		assert.False(t, allowed)
	}
}

func TestInterfaceFilter_InterfaceIPs(t *testing.T) {
	mockIPByIface := func(iface string) ([]netip.Addr, error) {
		switch iface {
		case "eth0":
			return []netip.Addr{netip.MustParsePrefix("198.51.100.1/24").Addr()}, nil

		case "eth1":
			return []netip.Addr{netip.MustParsePrefix("198.51.100.2/24").Addr()}, nil

		case "eth2":
			return []netip.Addr{netip.MustParsePrefix("2001:db8::1/32").Addr(), netip.MustParsePrefix("198.51.100.3/24").Addr()}, nil

		case "eth3":
			return []netip.Addr{netip.MustParsePrefix("2001:db8::2/32").Addr()}, nil

		case "eth4":
			return []netip.Addr{netip.MustParsePrefix("192.0.2.120/24").Addr()}, nil

		default:
			panic("unexpected interface name")
		}
	}

	ifaces, err := initIPInterfaceFilter([]string{"198.51.100.1/32", "2001:db8::1/128", "192.0.2.0/24"}, mockIPByIface)
	require.NoError(t, err)

	// Allowed
	for _, iface := range []string{"eth0", "eth2", "eth4"} {
		allowed, err := ifaces.Allowed(iface)
		require.NoError(t, err)
		assert.True(t, allowed)
	}
	// Not Allowed
	for _, iface := range []string{"eth1", "eth3"} {
		allowed, err := ifaces.Allowed(iface)
		require.NoError(t, err)
		assert.False(t, allowed)
	}
}
