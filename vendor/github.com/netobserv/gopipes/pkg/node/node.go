// Package node provides functionalities to create nodes and interconnect them.
// A Node is a function container that can be connected via channels to other nodes.
// A node can send data to multiple nodes, and receive data from multiple nodes.
package node

import (
	"fmt"
	"reflect"

	"github.com/netobserv/gopipes/pkg/internal/connect"
	"github.com/netobserv/gopipes/pkg/internal/refl"
)

// InitFunc is a function that receives a writable channel as unique argument, and sends
// value to that channel during an indefinite amount of time.
// TODO: with Go 1.18, this will be
// type InitFunc[OUT any] func(out chan<- OUT)
type InitFunc interface{}

// MiddleFunc is a function that receives a readable channel as first argument,
// and a writable channel as second argument.
// It must process the inputs from the input channel until it's closed.
// TODO: with Go 1.18, this will be
// type MiddleFunc[IN, OUT any] func(in <-chan IN, out chan<- OUT)
type MiddleFunc interface{}

// TerminalFunc is a function that receives a readable channel as unique argument.
// It must process the inputs from the input channel until it's closed.
// TODO: with Go 1.18, this will be
// type TerminalFunc[IN any] func(out <-chan IN)
type TerminalFunc interface{}

// Sender is any node that can send data to another node: node.Init and node.Middle
type Sender interface {
	// SendsTo connect a sender with a group of receivers
	SendsTo(...Receiver)
	// OutType returns the inner type of the Sender's output channel
	OutType() reflect.Type
}

// Receiver is any node that can receive data from another node: node.Middle and node.Terminal
type Receiver interface {
	startable
	joiner() *connect.Joiner
	// InType returns the inner type of the Receiver's input channel
	InType() reflect.Type
}

type startable interface {
	isStarted() bool
	start()
}

// Init nodes are the starting points of a graph. This is, all the nodes that bring information
// from outside the graph: e.g. because they generate them or because they acquire them from an
// external source like a Web Service.
// A graph must have at least one Init node.
// An Init node must have at least one output node.
type Init struct {
	outs    []Receiver
	fun     refl.Function
	outType reflect.Type
}

func (s *Init) SendsTo(outputs ...Receiver) {
	assertChannelsCompatibility(s.fun.ArgChannelType(0), outputs)
	s.outs = append(s.outs, outputs...)
}

func (s *Init) OutType() reflect.Type {
	return s.outType
}

// Middle is any intermediate node that receives data from another node, processes/filters it,
// and forwards the data to another node.
// An Middle node must have at least one output node.
type Middle struct {
	outs    []Receiver
	inputs  connect.Joiner
	started bool
	fun     refl.Function
	outType reflect.Type
	inType  reflect.Type
}

func (i *Middle) joiner() *connect.Joiner {
	return &i.inputs
}

func (i *Middle) isStarted() bool {
	return i.started
}

func (s *Middle) SendsTo(outputs ...Receiver) {
	assertChannelsCompatibility(s.fun.ArgChannelType(1), outputs)
	s.outs = append(s.outs, outputs...)
}

func (m *Middle) OutType() reflect.Type {
	return m.outType
}

func (m *Middle) InType() reflect.Type {
	return m.inType
}

// Terminal is any node that receives data from another node and does not forward it to another node,
// but can process it and send the results to outside the graph (e.g. memory, storage, web...)
type Terminal struct {
	inputs  connect.Joiner
	started bool
	fun     refl.Function
	done    chan struct{}
	inType  reflect.Type
}

func (i *Terminal) joiner() *connect.Joiner {
	return &i.inputs
}

func (t *Terminal) isStarted() bool {
	return t.started
}

// Done returns a channel that is closed when the Terminal node has ended its processing. This
// is, when all its inputs have been also closed. Waiting for all the Terminal nodes to finish
// allows blocking the execution until all the data in the graph has been processed and all the
// previous stages have ended
func (t *Terminal) Done() <-chan struct{} {
	return t.done
}

func (m *Terminal) InType() reflect.Type {
	return m.inType
}

// AsInit wraps an InitFunc into an Init node. It panics if the InitFunc does not follow the
// func(chan<-) signature.
func AsInit(fun InitFunc) *Init {
	fn := refl.WrapFunction(fun)
	fn.AssertNumberOfArguments(1)
	if !fn.ArgChannelType(0).CanSend() {
		panic(fn.String() + " first argument should be a writable channel")
	}
	return &Init{
		fun:     fn,
		outType: fn.ArgChannelType(0).ElemType(),
	}
}

// AsMiddle wraps an MiddleFunc into an Middle node, allowing to configure some instantiation
// parameters by means of an optional list of node.CreationOption.
// It panics if the MiddleFunc does not follow the func(<-chan,chan<-) signature.
func AsMiddle(fun MiddleFunc, opts ...CreationOption) *Middle {
	fn := refl.WrapFunction(fun)
	// check that the arguments are a read channel and a write channel
	fn.AssertNumberOfArguments(2)
	inCh := fn.ArgChannelType(0)
	if !inCh.CanReceive() {
		panic(fn.String() + " first argument should be a readable channel")
	}
	outCh := fn.ArgChannelType(1)
	if !outCh.CanSend() {
		panic(fn.String() + " second argument should be a writable channel")
	}
	options := getOptions(opts...)
	return &Middle{
		inputs:  connect.NewJoiner(inCh, options.channelBufferLen),
		fun:     fn,
		inType:  inCh.ElemType(),
		outType: outCh.ElemType(),
	}
}

// AsTerminal wraps a TerminalFunc into a Terminal node, allowing to configure some instantiation
// parameters by means of an optional list of node.CreationOption.
// It panics if the TerminalFunc does not follow the func(<-chan) signature.
func AsTerminal(fun TerminalFunc, opts ...CreationOption) *Terminal {
	fn := refl.WrapFunction(fun)
	// check that the arguments are only a read channel
	fn.AssertNumberOfArguments(1)
	inCh := fn.ArgChannelType(0)
	if !inCh.CanReceive() {
		panic(fn.String() + " first argument should be a readable channel")
	}
	options := getOptions(opts...)
	return &Terminal{
		inputs: connect.NewJoiner(inCh, options.channelBufferLen),
		fun:    fn,
		done:   make(chan struct{}),
		inType: inCh.ElemType(),
	}
}

func (i *Init) Start() {
	if len(i.outs) == 0 {
		panic("Init node should have outputs")
	}
	joiners := make([]*connect.Joiner, 0, len(i.outs))
	for _, out := range i.outs {
		joiners = append(joiners, out.joiner())
		if !out.isStarted() {
			out.start()
		}
	}
	forker := connect.Fork(joiners...)
	i.fun.RunAsStartGoroutine(forker.Sender(), forker.Close)
}

func (i *Middle) start() {
	if len(i.outs) == 0 {
		panic("Middle node should have outputs")
	}
	i.started = true
	joiners := make([]*connect.Joiner, 0, len(i.outs))
	for _, out := range i.outs {
		joiners = append(joiners, out.joiner())
		if !out.isStarted() {
			out.start()
		}
	}
	forker := connect.Fork(joiners...)
	i.fun.RunAsMiddleGoroutine(
		i.inputs.Receiver(),
		forker.Sender(),
		forker.Close)
}

func (t *Terminal) start() {
	t.started = true
	t.fun.RunAsEndGoroutine(t.inputs.Receiver(), func() {
		close(t.done)
	})
}

func assertChannelsCompatibility(srcInputType refl.ChannelType, outputs []Receiver) {
	for _, out := range outputs {
		switch t := out.(type) {
		case *Middle:
			srcInputType.AssertCanSendTo(t.fun.ArgChannelType(0))
		case *Terminal:
			srcInputType.AssertCanSendTo(t.fun.ArgChannelType(0))
		default:
			panic(fmt.Sprintf("unknown Receiver implementor %T. This is a bug! fix it", out))
		}
	}
}

func getOptions(opts ...CreationOption) creationOptions {
	options := defaultOptions
	for _, opt := range opts {
		opt(&options)
	}
	return options
}
