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
		ifs <- ifaces.Event{Type: ifaces.EventAdded, Interface: &i}
	}
	return ifs, nil
}

// func NewSimplestInterface(index int, name string) ifaces.Interface {
// 	return NewSimpleInterface(index, name, [6]uint8{})
// }

// func NewSimpleInterface(index int, name string, mac [6]uint8) ifaces.Interface {
// 	return ifaces.NewInterface(index, name, mac, 0, "")
// }
