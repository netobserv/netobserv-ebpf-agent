package flows

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	require.NoError(t, Validate(&Features{}))

	err := Validate(&Features{EnableDNSTracking: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ENABLE_DNS_TRACKING")
}
