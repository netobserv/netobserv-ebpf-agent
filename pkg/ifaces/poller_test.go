package ifaces

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"
)

const timeout = 5 * time.Second

func TestPoller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// fake net.Interfaces implementation that returns two different sets of
	// interfaces on successive invocations
	firstInvocation := true
	var fakeInterfaces = func() ([]Interface, error) {
		if firstInvocation {
			firstInvocation = false
			return []Interface{{"foo", 1, netns.None()}, {"bar", 2, netns.None()}}, nil
		}
		return []Interface{{"foo", 1, netns.None()}, {"bae", 3, netns.None()}}, nil
	}
	poller := NewPoller(5*time.Millisecond, 10)
	poller.interfaces = fakeInterfaces

	updates, err := poller.Subscribe(ctx)
	require.NoError(t, err)
	// first poll: two interfaces are added
	assert.Equal(t,
		Event{Type: EventAdded, Interface: Interface{"foo", 1, netns.None()}},
		getEvent(t, updates, timeout))
	assert.Equal(t,
		Event{Type: EventAdded, Interface: Interface{"bar", 2, netns.None()}},
		getEvent(t, updates, timeout))
	// second poll: one interface is added and another is removed
	assert.Equal(t,
		Event{Type: EventAdded, Interface: Interface{"bae", 3, netns.None()}},
		getEvent(t, updates, timeout))
	assert.Equal(t,
		Event{Type: EventDeleted, Interface: Interface{"bar", 2, netns.None()}},
		getEvent(t, updates, timeout))
	// successive polls: no more events are forwarded
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
