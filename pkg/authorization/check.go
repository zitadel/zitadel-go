package authorization

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrMissingRole  = func(role string) error { return fmt.Errorf("missing required role: `%s`", role) }
)

type Verifier[T Ctx] interface {
	CheckAuthorization(ctx context.Context, accessToken string) (T, error)
}

type NewVerifier[T Ctx] func(ctx context.Context, domain string) (Verifier[T], error)

type Check[T Ctx] struct {
	Checks []func(authCtx T) error
}

type Cache[T Ctx] interface {
	Get(token string) T
	Set(token string, value T)
}

type CheckOption func(*Check[Ctx])

func WithRole(role string) CheckOption {
	return func(check *Check[Ctx]) {
		check.Checks = append(check.Checks, func(authCtx Ctx) error {
			if authCtx.IsGrantedRole(role) {
				return nil
			}
			return ErrMissingRole(role)
		})
	}
}

func (a *Authorizer[T]) CheckAuthorization(ctx context.Context, token string, options ...CheckOption) (authCtx T, err error) {
	var t T
	check := new(Check[Ctx])
	for _, option := range options {
		option(check)
	}
	authCtx, err = a.verifier.CheckAuthorization(ctx, token)
	if err != nil || !authCtx.IsAuthorized() {
		return t, NewError(ErrUnauthorized, err)
	}
	for _, c := range check.Checks {
		if err = c(authCtx); err != nil {
			return t, NewError(ErrUnauthorized, err)
		}
	}
	return authCtx, nil
}

type Authorizer[T Ctx] struct {
	verifier Verifier[T]
}

type Option[T Ctx] func(authorizer *Authorizer[T])

func New[T Ctx](ctx context.Context, domain string, newVerifier NewVerifier[T], options ...Option[T]) (*Authorizer[T], error) {
	verifier, err := newVerifier(ctx, domain)
	if err != nil {
		return nil, err
	}
	authorizer := &Authorizer[T]{
		verifier: verifier,
	}
	for _, option := range options {
		option(authorizer)
	}
	return authorizer, nil
}
