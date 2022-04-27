package ifaces

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventsInformer_Poller(t *testing.T) {
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

	changes, err := Informer(ctx, poller, 10)
	require.NoError(t, err)

	assert.Equal(t, Event{Type: EventAdded, Interface: "foo"}, getEvent(t, changes))
	assert.Equal(t, Event{Type: EventAdded, Interface: "bar"}, getEvent(t, changes))
	assert.Equal(t, Event{Type: EventAdded, Interface: "bae"}, getEvent(t, changes))
	assert.Equal(t, Event{Type: EventDeleted, Interface: "bar"}, getEvent(t, changes))

	select {
	case ev, ok := <-changes:
		assert.Falsef(t, ok, "no more events were expected. Received: %+v", ev)
	default:
		// ok!
	}
}

func TestEventsInformer_Watcher(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	procNetDev, err := ioutil.TempFile("", "test_watcher")
	require.NoError(t, err)
	_, err = procNetDev.WriteString(`Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
       eth0:     746       7    0    0    0     0          0         0      656       8    0    0    0     0       0          0
ovn-k8s-mp0: 36061227  194651    0    0    0     0          0         0 114387109  233912    0    0    0     0       0          0
a242730663491d7: 1614408163  178131    0    0    0     0          0         0 133433479  166346    0    0    0     0       0          0
         lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
`)
	require.NoError(t, err)
	require.NoError(t, procNetDev.Close())

	watcher := NewWatcher(procNetDev.Name(), 10)

	changes, err := Informer(ctx, watcher, 10)
	require.NoError(t, err)

	require.Equal(t, Event{Type: EventAdded, Interface: "eth0"}, getEvent(t, changes))
	require.Equal(t, Event{Type: EventAdded, Interface: "ovn-k8s-mp0"}, getEvent(t, changes))
	require.Equal(t, Event{Type: EventAdded, Interface: "a242730663491d7"}, getEvent(t, changes))
	require.Equal(t, Event{Type: EventAdded, Interface: "lo"}, getEvent(t, changes))

	procNetDev, err = os.Create(procNetDev.Name())
	require.NoError(t, err)
	_, err = procNetDev.WriteString(`Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
       eth0:     746       7    0    0    0     0          0         0      656       8    0    0    0     0       0          0
8d8aeebe36fc23b: 1614408163  178131    0    0    0     0          0         0 133433479  166346    0    0    0     0       0          0
ovn-k8s-mp0: 36061227  194651    0    0    0     0          0         0 114387109  233912    0    0    0     0       0          0
abcdefghijk: 1614408163  178131    0    0    0     0          0         0 133433479  166346    0    0    0     0       0          0
         lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
`)
	require.NoError(t, err)
	require.NoError(t, procNetDev.Close())

	require.Equal(t, Event{Type: EventAdded, Interface: "8d8aeebe36fc23b"}, getEvent(t, changes))
	require.Equal(t, Event{Type: EventAdded, Interface: "abcdefghijk"}, getEvent(t, changes))
	require.Equal(t, Event{Type: EventDeleted, Interface: "a242730663491d7"}, getEvent(t, changes))

	select {
	case ev, ok := <-changes:
		assert.Falsef(t, ok, "no more events were expected. Received: %+v", ev)
	default:
		// ok!
	}
}

func getEvent(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case event := <-ch:
		return event
	case <-time.After(timeout):
		require.Fail(t, "timeout while waiting for an event")
	}
	return Event{}
}
