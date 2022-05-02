package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInterfaces_DefaultConfig(t *testing.T) {
	ifaces, err := initInterfaceFilter(nil, []string{"lo"})
	require.NoError(t, err)

	assert.True(t, ifaces.Allowed("eth0"))
	assert.True(t, ifaces.Allowed("br-0"))
	assert.False(t, ifaces.Allowed("lo"))
}

func TestInterfaceFilter_SelectingInterfaces_DefaultExclusion(t *testing.T) {
	ifaces, err := initInterfaceFilter([]string{"eth0", "/^br-/"}, []string{"lo"})
	require.NoError(t, err)

	assert.True(t, ifaces.Allowed("eth0"))
	assert.True(t, ifaces.Allowed("br-0"))
	assert.False(t, ifaces.Allowed("eth01"))
	assert.False(t, ifaces.Allowed("abr-3"))
	assert.False(t, ifaces.Allowed("lo"))
}

func TestInterfaceFilter_ExclusionTakesPriority(t *testing.T) {

	ifaces, err := initInterfaceFilter([]string{"/^eth/", "/^br-/"}, []string{"eth1", "/^br-1/"})
	require.NoError(t, err)

	assert.True(t, ifaces.Allowed("eth0"))
	assert.True(t, ifaces.Allowed("eth10"))
	assert.True(t, ifaces.Allowed("eth11"))
	assert.True(t, ifaces.Allowed("br-2"))
	assert.True(t, ifaces.Allowed("br-0"))
	assert.False(t, ifaces.Allowed("eth1"))
	assert.False(t, ifaces.Allowed("br-1"))
	assert.False(t, ifaces.Allowed("br-10"))
}
