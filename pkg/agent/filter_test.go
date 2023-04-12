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
		iface := iface
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
		iface := iface
		allowed, err := ifaces.Allowed(iface)
		require.NoError(t, err)
		assert.True(t, allowed)
	}
	// Not Allowed
	for _, iface := range []string{"eth01", "abr-3", "lo"} {
		iface := iface
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
		iface := iface
		allowed, err := ifaces.Allowed(iface)
		require.NoError(t, err)
		assert.True(t, allowed)
	}
	// Not Allowed
	for _, iface := range []string{"eth1", "br-1", "br-10"} {
		iface := iface
		allowed, err := ifaces.Allowed(iface)
		require.NoError(t, err)
		assert.False(t, allowed)
	}
}

func TestInterfaceFilter_InterfaceIPs(t *testing.T) {
	mockIPByIface := func(iface string) ([]netip.Prefix, error) {
		switch iface {
		case "eth0":
			return []netip.Prefix{netip.MustParsePrefix("198.51.100.1/24")}, nil

		case "eth1":
			return []netip.Prefix{netip.MustParsePrefix("198.51.100.2/24")}, nil

		default:
			panic("unexpected interface name")
		}
	}

	ifaces, err := initIPInterfaceFilter([]string{"198.51.100.1/24"}, mockIPByIface)
	require.NoError(t, err)

	// Allowed
	for _, iface := range []string{"eth0"} {
		iface := iface
		allowed, err := ifaces.Allowed(iface)
		require.NoError(t, err)
		assert.True(t, allowed)
	}
	// Not Allowed
	for _, iface := range []string{"eth1"} {
		iface := iface
		allowed, err := ifaces.Allowed(iface)
		require.NoError(t, err)
		assert.False(t, allowed)
	}
}
