package authorization

import (
	"errors"
)

// UnauthorizedErr is used to provide the information to the caller, that the provided authorization
// is invalid (missing, wrong format, expired, ...).
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
	return errors.Is(e.err, t.err)
}

func (e *UnauthorizedErr) Unwrap() error {
	return e.err
}

// PermissionDeniedErr is used to provide the information to the caller, that the provided authorization
// was valid but not sufficient (missing role).
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
	return errors.Is(e.err, t.err)
}

func (e *PermissionDeniedErr) Unwrap() error {
	return e.err
}
