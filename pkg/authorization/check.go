package authorization

import (
	"context"
	"errors"
	"fmt"
)

const (
	HeaderName = "authorization"
)

var (
	ErrEmptyAuthorizationHeader = errors.New("authorization header is empty")
	ErrMissingRole              = errors.New("missing required role")
)

// Authorizer provides the functionality to check for authorization such as token verification including role checks.
type Authorizer[T Ctx] struct {
	verifier Verifier[T]
}

// Option allows customization of the [Authorizer] such as caching and more.
type Option[T Ctx] func(authorizer *Authorizer[T])

func New[T Ctx](ctx context.Context, domain string, initVerifier VerifierInitializer[T], options ...Option[T]) (*Authorizer[T], error) {
	verifier, err := initVerifier(ctx, domain)
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

// CheckAuthorization will verify the token using the configured [Verifier] and provided [Check]
func (a *Authorizer[T]) CheckAuthorization(ctx context.Context, token string, options ...CheckOption) (authCtx T, err error) {
	var t T
	if token == "" {
		return t, NewErrorUnauthorized(ErrEmptyAuthorizationHeader)
	}
	checks := new(Check[Ctx])
	for _, option := range options {
		option(checks)
	}
	authCtx, err = a.verifier.CheckAuthorization(ctx, token)
	if err != nil || !authCtx.IsAuthorized() {
		return t, NewErrorUnauthorized(err)
	}
	for _, c := range checks.Checks {
		if err = c(authCtx); err != nil {
			return t, NewErrorPermissionDenied(err)
		}
	}
	return authCtx, nil
}

// Verifier defines the possible verification checks such as validation of the authorizationToken.
type Verifier[T Ctx] interface {
	CheckAuthorization(ctx context.Context, authorizationToken string) (T, error)
}

// VerifierInitializer abstracts the initialization of a [Verifier] by providing the ZITADEL domain
type VerifierInitializer[T Ctx] func(ctx context.Context, domain string) (Verifier[T], error)

// Check will be executed during the authorization check and provide a mechanism to require additional permission such as a role.
// There will be options, e.g. caching and more in the near future.
type Check[T Ctx] struct {
	Checks []func(authCtx T) error
}

// CheckOption allows customization of the [Check] like additional permission requirements (e.g. roles)
type CheckOption func(*Check[Ctx])

// WithRole requires the authorized user to be granted the provided role.
// If the role is not granted to the user, an [ErrMissingRole] is returned.
func WithRole(role string) CheckOption {
	return func(checks *Check[Ctx]) {
		checks.Checks = append(checks.Checks, func(authCtx Ctx) error {
			if authCtx.IsGrantedRole(role) {
				return nil
			}
			return fmt.Errorf("%w: `%s`", ErrMissingRole, role)
		})
	}
}
