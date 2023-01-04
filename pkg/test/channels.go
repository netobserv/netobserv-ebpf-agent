package test

import (
	"testing"
	"time"
)

// ReceiveTimeout returns the first received element or fails the test if nothing is received
// before the given timeout
func ReceiveTimeout[T any](t *testing.T, ch <-chan T, timeout time.Duration) T {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(timeout):
		var z T
		t.Fatalf("timeout while waiting %s for a %T element in channel", timeout, z)
		return z
	}
}
