package tracer

type Error struct {
	inner error
	Name  string
}

func NewError(name string, err error) *Error {
	return &Error{
		inner: err,
		Name:  name,
	}
}

func (e *Error) Error() string {
	return e.inner.Error()
}
