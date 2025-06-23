package tracer

type Error struct {
	inner      error
	Name       string
	DoNotRetry bool
}

func NewError(name string, err error) *Error {
	return &Error{
		inner: err,
		Name:  name,
	}
}

func NewErrorNoRetry(name string, err error) *Error {
	return &Error{
		inner:      err,
		Name:       name,
		DoNotRetry: true,
	}
}

func (e *Error) Error() string {
	s := e.inner.Error()
	if e.DoNotRetry {
		return s + " (no retry)"
	}
	return s
}
