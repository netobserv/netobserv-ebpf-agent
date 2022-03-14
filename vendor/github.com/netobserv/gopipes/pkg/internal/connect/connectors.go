package connect

import (
	"sync/atomic"

	"github.com/netobserv/gopipes/pkg/internal/refl"
)

// Joiner provides shared access to the input channel of a node.
type Joiner struct {
	channelType  refl.ChannelType
	totalSenders int32
	bufLen       int
	channel      refl.Channel
}

// NewJoiner creates a joiner for a given channel type and buffer length
func NewJoiner(ct refl.ChannelType, bufferLength int) Joiner {
	return Joiner{
		channelType: ct,
		bufLen:      bufferLength,
		channel:     ct.Instantiate(bufferLength),
	}
}

// Receiver gets access to the channel as a receiver
func (j *Joiner) Receiver() refl.Channel {
	return j.channel
}

// AcquireSender gets acces to the channel as a sender. The acquirer must finally invoke
// ReleaseSender to make sure that the channel is closed when all the senders released it.
func (j *Joiner) AcquireSender() refl.Channel {
	atomic.AddInt32(&j.totalSenders, 1)
	return j.channel
}

// ReleaseSender will close the channel when all the invokers of the AcquireSender have invoked
// this function
func (j *Joiner) ReleaseSender() {
	// if no senders, we close the main channel
	if atomic.AddInt32(&j.totalSenders, -1) == 0 {
		j.channel.Close()
	}
}

// Releaser is a function that will allow releasing a forked channel.
type Releaser func()

// Forker manages the access to a Node's output (send) channel. When a node sends to only
// one node, this will work as a single channel. When a node sends to N nodes,
// it will spawn N channels that are cloned from the original channel in a goroutine.
type Forker struct {
	sendCh         refl.Channel
	releaseChannel Releaser
}

// Fork provides connection to a group of output Nodes, accessible through their respective
// Joiner instances.
func Fork(joiners ...*Joiner) Forker {
	if len(joiners) == 0 {
		panic("can't fork 0 joiners")
	}
	// if there is only one joiner, we directly send the data to the channel, without intermediation
	if len(joiners) == 1 {
		return Forker{
			sendCh:         joiners[0].AcquireSender(),
			releaseChannel: joiners[0].ReleaseSender,
		}
	}
	// assuming all the channels are from the same type (previously verified)
	chType := joiners[0].channelType
	// channel used as input from the source Node
	sendCh := chType.Instantiate(joiners[0].bufLen)

	// channels that clone the contents of the sendCh
	forwarders := make([]refl.Channel, len(joiners))
	for i := 0; i < len(joiners); i++ {
		forwarders[i] = joiners[i].AcquireSender()
	}
	go func() {
		for in, ok := sendCh.Recv(); ok; in, ok = sendCh.Recv() {
			for i := 0; i < len(joiners); i++ {
				forwarders[i].Send(in)
			}
		}
		for i := 0; i < len(joiners); i++ {
			joiners[i].ReleaseSender()
		}
	}()
	return Forker{
		sendCh:         sendCh,
		releaseChannel: sendCh.Close,
	}
}

// Sender acquires the channel that will receive the data from the source node
func (f *Forker) Sender() refl.Channel {
	return f.sendCh
}

// Close the input channel and, in cascade, all the forked channels
func (f *Forker) Close() {
	f.releaseChannel()
}
