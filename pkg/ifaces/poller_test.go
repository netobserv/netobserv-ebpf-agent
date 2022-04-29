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

	poller := NewPoller(5*time.Millisecond, 10)
	poller.interfaces = fakeInterfaces

	updates, err := poller.Subscribe(ctx)
	require.NoError(t, err)

	assert.Equal(t, Event{Type: EventAdded, Interface: "foo"}, getEvent(t, updates, timeout))
	assert.Equal(t, Event{Type: EventAdded, Interface: "bar"}, getEvent(t, updates, timeout))
	assert.Equal(t, Event{Type: EventAdded, Interface: "bae"}, getEvent(t, updates, timeout))
	assert.Equal(t, Event{Type: EventDeleted, Interface: "bar"}, getEvent(t, updates, timeout))

	// no more events are forwarded
	select {
	case ev := <-updates:
		require.Failf(t, "unexpected event", "%#v", ev)
	default:
		// ok!
	}
}

func getEvent(t *testing.T, ch <-chan Event, timeout time.Duration) Event {
	t.Helper()
	select {
	case event := <-ch:
		return event
	case <-time.After(timeout):
		require.Fail(t, "timeout while waiting for an event")
	}
	return Event{}
}
