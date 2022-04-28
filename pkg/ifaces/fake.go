package ifaces

import (
	"context"
)

type FakeNameProvider struct {
	wait     chan struct{}
	ticks    int
	Provides [][]Name
}

// Next triggers the submission the next bunch of discovered interfaces
func (f *FakeNameProvider) Next() {
	f.wait <- struct{}{}
}

func (f *FakeNameProvider) Subscribe(ctx context.Context) (<-chan []Name, error) {
	interfacesCh := make(chan []Name, 1)
	go func() {
		f.wait = make(chan struct{}, 1)
		defer close(f.wait)
		for {
			if f.ticks < len(f.Provides) {
				interfacesCh <- f.Provides[f.ticks]
				f.ticks++
			} else {
				interfacesCh <- []Name{}
			}
			select {
			case <-ctx.Done():
				// test finished
				return
			case <-f.wait:
				// go to the next iteration to send the following interfaces
			}
		}
	}()
	return interfacesCh, nil
}
