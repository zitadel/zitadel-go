package authorization

import "errors"

type UnauthorizedErr struct {
	err error
}

func NewErrorUnauthorized(err error) *UnauthorizedErr {
	return &UnauthorizedErr{
		err: err,
	}
}

func (e *UnauthorizedErr) Error() string {
	if e.err == nil {
		return "unauthorized"
	}
	return e.err.Error()
}

func (e *UnauthorizedErr) Is(target error) bool {
	t, ok := target.(*UnauthorizedErr)
	if !ok {
		return false
	}
	if t.err == nil {
		return true
	}
	return errors.Is(t.err, e.err)
}

type PermissionDeniedErr struct {
	err error
}

func NewErrorPermissionDenied(err error) *PermissionDeniedErr {
	return &PermissionDeniedErr{
		err: err,
	}
}

func (e *PermissionDeniedErr) Error() string {
	if e.err == nil {
		return "permission denied"
	}
	return e.err.Error()
}

func (e *PermissionDeniedErr) Is(target error) bool {
	t, ok := target.(*PermissionDeniedErr)
	if !ok {
		return false
	}
	if t.err == nil {
		return true
	}
	return errors.Is(t.err, e.err)
}
