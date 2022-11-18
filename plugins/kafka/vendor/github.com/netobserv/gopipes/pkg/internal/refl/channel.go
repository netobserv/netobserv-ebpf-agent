package refl

import (
	"fmt"
	"reflect"
)

// Channel wraps a channel for its usage with refl.Function objects
type Channel struct {
	reflect.Value
}

// ChannelType wraps a channel type
type ChannelType struct {
	inner reflect.Type
}

func makeChannel(inType reflect.Type, bufLen int) reflect.Value {
	chanType := reflect.ChanOf(reflect.BothDir, inType)
	return reflect.MakeChan(chanType, bufLen)
}

func (ch ChannelType) CanSend() bool {
	return ch.inner.ChanDir()&reflect.SendDir != 0
}

func (ch *ChannelType) CanReceive() bool {
	return ch.inner.ChanDir()&reflect.RecvDir != 0
}

func (ch *ChannelType) Instantiate(bufLen int) Channel {
	return Channel{makeChannel(ch.inner.Elem(), bufLen)}
}

func (ch *ChannelType) AssertCanSendTo(dst ChannelType) {
	if !ch.inner.Elem().AssignableTo(dst.inner.Elem()) {
		panic(fmt.Sprintf("%s can't send data to %s", ch.inner, dst.inner))
	}
}

func (ch ChannelType) ElemType() reflect.Type {
	return ch.inner.Elem()
}
