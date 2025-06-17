package ifaces

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"
)

const (
	timeout = 5 * time.Second
)

var (
	macFoo        = [6]uint8{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	macBar        = [6]uint8{0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	macBaz        = [6]uint8{0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	macBae        = [6]uint8{0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	macOverlapped = [6]uint8{0x05, 0x06, 0x07, 0x08, 0x09, 0x0a}
)

func simpleInterface(index int, name string, mac [6]uint8) Interface {
	return NewInterface(index, name, mac, netns.None(), "")
}

func simpleInterfacePtr(index int, name string, mac [6]uint8) *Interface {
	i := simpleInterface(index, name, mac)
	return &i
}

func TestPoller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// fake net.Interfaces implementation that returns two different sets of
	// interfaces on successive invocations, with overlapping Index
	firstInvocation := true
	var fakeInterfaces = func(_ netns.NsHandle, _ string) ([]Interface, error) {
		if firstInvocation {
			firstInvocation = false
			return []Interface{
				simpleInterface(1, "foo", macFoo),
				simpleInterface(2, "bar", macBar),
				simpleInterface(4, "bae", macBae),
			}, nil
		}
		return []Interface{
			simpleInterface(1, "foo", macFoo),
			simpleInterface(3, "baz", macBaz),
			simpleInterface(4, "ovlp", macOverlapped),
		}, nil
	}
	poller := NewPoller(5*time.Millisecond, 10)
	poller.interfaces = fakeInterfaces

	updates, err := poller.Subscribe(ctx)
	require.NoError(t, err)
	// first poll: two interfaces are added
	assert.Equal(t,
		Event{Type: EventAdded, Interface: simpleInterfacePtr(1, "foo", macFoo)},
		getEvent(t, updates, timeout))
	assert.Equal(t,
		Event{Type: EventAdded, Interface: simpleInterfacePtr(2, "bar", macBar)},
		getEvent(t, updates, timeout))
	assert.Equal(t,
		Event{Type: EventAdded, Interface: simpleInterfacePtr(4, "bae", macBae)},
		getEvent(t, updates, timeout))
	// second poll: one interface is added and another is removed
	assert.Equal(t,
		Event{Type: EventAdded, Interface: simpleInterfacePtr(3, "baz", macBaz)},
		getEvent(t, updates, timeout))
	assert.Equal(t,
		Event{Type: EventAdded, Interface: simpleInterfacePtr(4, "ovlp", macOverlapped)},
		getEvent(t, updates, timeout))
	// Order isn't guaranteed for next events, so use assert.ElementsMatch
	next1 := getEvent(t, updates, timeout)
	next2 := getEvent(t, updates, timeout)
	assert.ElementsMatch(t,
		[]Event{next1, next2},
		[]Event{
			{Type: EventDeleted, Interface: simpleInterfacePtr(2, "bar", macBar)},
			{Type: EventDeleted, Interface: simpleInterfacePtr(4, "bae", macBae)},
		},
	)

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
