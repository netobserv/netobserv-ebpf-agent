package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJoinHostPort(t *testing.T) {
	assert.Equal(t, "[::1]:443", JoinHostPort("::1", 443))
	assert.Equal(t, "[::1]:443", JoinHostPort("[::1]", 443))
	assert.Equal(t, "localhost:443", JoinHostPort("localhost", 443))
	assert.Equal(t, "127.0.0.1:443", JoinHostPort("127.0.0.1", 443))
	assert.Equal(t, ":0", JoinHostPort("", 0))
}
