package ifaces

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWatcher(t *testing.T) {
	logrus.StandardLogger().SetLevel(logrus.DebugLevel)
	ctx, cancel := context.WithCancel(context.Background())
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
	updates, err := watcher.Subscribe(ctx)
	require.NoError(t, err)

	select {
	case names := <-updates:
		assert.Equal(t, []Name{"eth0", "ovn-k8s-mp0", "a242730663491d7", "lo"}, names)
	case <-time.After(timeout):
		require.Fail(t, "timeout while waiting for interface names")
	}

	procNetDev, err = os.Create(procNetDev.Name())
	require.NoError(t, err)
	_, err = procNetDev.WriteString(`Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
       eth0:     746       7    0    0    0     0          0         0      656       8    0    0    0     0       0          0
8d8aeebe36fc23b: 1614408163  178131    0    0    0     0          0         0 133433479  166346    0    0    0     0       0          0
ovn-k8s-mp0: 36061227  194651    0    0    0     0          0         0 114387109  233912    0    0    0     0       0          0
         lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
`)
	require.NoError(t, err)
	require.NoError(t, procNetDev.Close())

	select {
	case names := <-updates:
		assert.Equal(t, []Name{"eth0", "8d8aeebe36fc23b", "ovn-k8s-mp0", "lo"}, names)
	case <-time.After(timeout):
		require.Fail(t, "timeout while waiting for interface names")
	}

	cancel()

	procNetDev, err = os.Create(procNetDev.Name())
	require.NoError(t, err)
	_, err = procNetDev.WriteString(`Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
       eth0:     746       7    0    0    0     0          0         0      656       8    0    0    0     0       0          0
`)
	require.NoError(t, err)
	require.NoError(t, procNetDev.Close())

	select {
	case names, ok := <-updates:
		assert.Falsef(t, ok, "after canceling, no more updates are expected. Got %+v", names)
	case <-time.After(timeout):
		assert.Fail(t, "watcher should have been closed after canceling its context")
	}
}
