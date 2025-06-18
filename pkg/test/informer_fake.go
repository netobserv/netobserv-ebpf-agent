package test

import (
	"context"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
)

// SliceInformerFake fakes the ifaces.Informer implementation by just notifying all the
// interfaces in the slice
type SliceInformerFake []ifaces.Interface

func (sif SliceInformerFake) Subscribe(_ context.Context) (<-chan ifaces.Event, error) {
	ifs := make(chan ifaces.Event, len(sif))
	for _, i := range sif {
		ifs <- ifaces.Event{Type: ifaces.EventAdded, Interface: i}
	}
	return ifs, nil
}
