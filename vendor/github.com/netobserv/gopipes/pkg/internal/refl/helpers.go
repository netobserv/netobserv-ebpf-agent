package refl

import "reflect"

// some functions for syntactic sugar
func typeOf(fn *Function) reflect.Type {
	return (*reflect.Value)(fn).Type()
}

func valueOf(fn *Function) *reflect.Value {
	return (*reflect.Value)(fn)
}
