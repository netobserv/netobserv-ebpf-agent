package packets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	require.NoError(t, Validate(Features{}))

	err := Validate(Features{EnablePCA: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ENABLE_PCA")
}
