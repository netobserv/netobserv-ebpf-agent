package agent

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInterfaces(t *testing.T) {
	// Default configuration
	ifaces, err := getInterfaces(&Config{
		ExcludeInterfaces: []string{"lo"},
	}, interfacesMock)
	require.NoError(t, err)

	assert.Equal(t, map[string]struct{}{
		"eth0": {}, "eth1": {}, "veth0": {}, "veth1": {}, "br-0": {}, "br-1": {},
	}, ifaces)

	// Selecting interfaces, default exclusion
	ifaces, err = getInterfaces(&Config{
		Interfaces:        []string{"eth0", "/^br-/"},
		ExcludeInterfaces: []string{"lo"},
	}, interfacesMock)
	require.NoError(t, err)

	assert.Equal(t, map[string]struct{}{
		"eth0": {}, "br-0": {}, "br-1": {},
	}, ifaces)

	// Selecting & excluding interfaces. Exclusion takes priority
	ifaces, err = getInterfaces(&Config{
		Interfaces:        []string{"/^eth/"},
		ExcludeInterfaces: []string{"eth1"},
	}, interfacesMock)
	require.NoError(t, err)

	assert.Equal(t, map[string]struct{}{"eth0": {}}, ifaces)
}

func interfacesMock() ([]net.Interface, error) {
	return []net.Interface{
		{Name: "lo"},
		{Name: "eth0"}, {Name: "eth1"},
		{Name: "veth0"}, {Name: "veth1"},
		{Name: "br-0"}, {Name: "br-1"},
	}, nil
}
