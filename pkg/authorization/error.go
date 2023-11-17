package authorization

import "fmt"

type Error struct {
	err    error
	parent any
}

func NewError(err error, parent any) *Error {
	return &Error{
		err:    err,
		parent: parent,
	}
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %v", e.err.Error(), e.parent)
}
