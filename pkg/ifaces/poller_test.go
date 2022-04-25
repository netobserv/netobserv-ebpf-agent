package ifaces

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const timeout = 5 * time.Second

func TestPoller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	firstInvocation := true
	var fakeInterfaces = func() ([]Name, error) {
		if firstInvocation {
			firstInvocation = false
			return []Name{"foo", "bar"}, nil
		} else {
			return []Name{"foo", "bae"}, nil
		}
	}

	poller := NewPoller(5 * time.Millisecond)
	poller.interfaces = fakeInterfaces

	updates, err := poller.Subscribe(ctx)
	require.NoError(t, err)

	select {
	case names := <-updates:
		assert.Equal(t, []Name{"foo", "bar"}, names)
	case <-time.After(timeout):
		require.Fail(t, "timeout while waiting for poller to send interfaces")
	}

	select {
	case names := <-updates:
		assert.Equal(t, []Name{"foo", "bae"}, names)
	case <-time.After(timeout):
		require.Fail(t, "timeout while waiting for poller to send interfaces")
	}
}
