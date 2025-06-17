package tracer

type TracerError struct {
	inner error
	Name  string
}

func NewTracerError(name string, err error) *TracerError {
	return &TracerError{
		inner: err,
		Name:  name,
	}
}

func (e *TracerError) Error() string {
	return e.inner.Error()
}
