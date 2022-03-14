// Package refl wraps some reflection functionalities
package refl

import (
	"fmt"
	"reflect"
)

// Function wraps a reflect.Value and provides some common reflective assertions about its type
type Function reflect.Value

// WrapFunction wraps a provided function into a refl.Function object. It panics if
// the provided argument is not a function.
func WrapFunction(fn interface{}) Function {
	val := reflect.ValueOf(fn)
	if val.Kind() != reflect.Func {
		panic("expecting a function. Got: " + val.Kind().String())
	}
	return Function(val)
}

// String representation of the Function type
func (fn *Function) String() string {
	return typeOf(fn).String()
}

// AssertNumberOfArguments panics if the function does not have the given number of arguments
func (fn *Function) AssertNumberOfArguments(num int) {
	ftype := typeOf(fn)
	if ftype.NumIn() != num {
		// TODO: give information of the actual arguments
		panic(fmt.Sprintf("%s should have %d arguments. Has %d", ftype.Name(), num, ftype.NumIn()))
	}
}

// ArgChannelType returns the type of the channel in the numbered argumment.
// It panics if the argument in that position is not a channel
func (fn *Function) ArgChannelType(argNum int) ChannelType {
	ftype := typeOf(fn)
	arg := ftype.In(argNum)
	if arg.Kind() != reflect.Chan {
		panic(fmt.Sprintf("%s argument #%d should be a channel. Got: %d",
			ftype, argNum, arg.Kind()))
	}
	return ChannelType{inner: arg}
}

// RunAsStartGoroutine runs in a goroutine a func(out chan<- T) instance.
// It accepts a Channel where the data will be sent.
// The releaseFunc will be invoked when the wrapped function ends.
func (fn *Function) RunAsStartGoroutine(output Channel, releaseFunc func()) {
	outCh := output.Value
	go func() {
		defer releaseFunc()
		valueOf(fn).Call([]reflect.Value{outCh})
	}()
}

// RunAsEndGoroutine runs in a goroutine a func(in <-chan T) instance. It accepts a Channel
// to be used as input for data.
// The releaseFunc will be invoked when the wrapped function ends.
func (fn *Function) RunAsEndGoroutine(inCh Channel, releaseFunc func()) {
	go func() {
		defer releaseFunc()
		valueOf(fn).Call([]reflect.Value{inCh.Value})
	}()
}

// RunAsMiddleGoroutine runs in a goroutine a func(in <-chan T, out chan<- U) instance.
// It accepts two Channel to be used as input and output for the data.
// When the executed function is finished, the releaseFunc method is invoked.
func (fn *Function) RunAsMiddleGoroutine(input, output Channel, releaseFunc func()) {
	inCh := input.Value
	outCh := output.Value
	go func() {
		defer releaseFunc()
		valueOf(fn).Call([]reflect.Value{inCh, outCh})
	}()
}
