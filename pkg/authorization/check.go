package authorization

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

const (
	HeaderName = "authorization"
)

var (
	ErrEmptyAuthorizationHeader = errors.New("authorization header is empty")
	ErrMissingToken             = errors.New("missing or malformed token")
	ErrMissingRole              = errors.New("missing required role")
)

// checkForEmptyorMalformedToken validates the following scenarios:
// 1. Token header is empty
// 2. Token header does not equal "Bearer "
// 3. Token is empty after "Bearer " prefix
func checkForEmptyorMalformedToken(tokenHeader string) error {
	t := strings.TrimSpace(tokenHeader)
	token, ok := strings.CutPrefix(t, oidc.BearerToken+" ")
	if !ok || token == "" || tokenHeader == "" {
		return ErrMissingToken
	}
	return nil
}

// Authorizer provides the functionality to check for authorization such as token verification including role checks.
type Authorizer[T Ctx] struct {
	verifier Verifier[T]
	logger   *slog.Logger
}

// Option allows customization of the [Authorizer] such as caching, logging and more.
type Option[T Ctx] func(authorizer *Authorizer[T])

// WithLogger allows a logger other than slog.Default().
//
// EXPERIMENTAL: Will change to log/slog import after we drop support for Go 1.20
func WithLogger[T Ctx](logger *slog.Logger) Option[T] {
	return func(a *Authorizer[T]) {
		a.logger = logger
	}
}

func New[T Ctx](ctx context.Context, zitadel *zitadel.Zitadel, initVerifier VerifierInitializer[T], options ...Option[T]) (*Authorizer[T], error) {
	verifier, err := initVerifier(ctx, zitadel)
	if err != nil {
		return nil, err
	}
	authorizer := &Authorizer[T]{
		verifier: verifier,
		logger:   slog.Default(),
	}
	for _, option := range options {
		option(authorizer)
	}
	return authorizer, nil
}

// CheckAuthorization will verify the token using the configured [Verifier] and provided [Check]
func (a *Authorizer[T]) CheckAuthorization(ctx context.Context, token string, options ...CheckOption) (authCtx T, err error) {
	a.logger.Log(ctx, slog.LevelDebug, "checking authorization")
	var t T
	if err := checkForEmptyorMalformedToken(token); err != nil {
		a.logger.Log(ctx, slog.LevelWarn, "no authorization header")
		return t, NewErrorUnauthorized(err)
	}
	checks := new(Check[Ctx])
	for _, option := range options {
		option(checks)
	}
	authCtx, err = a.verifier.CheckAuthorization(ctx, token)
	if err != nil || !authCtx.IsAuthorized() {
		if err != nil && isServerError(err) {
			a.logger.With("error", err).Log(ctx, slog.LevelWarn, "service unavailable")
			return t, NewErrorServiceUnavailable(err)
		}
		a.logger.With("error", err).Log(ctx, slog.LevelWarn, "unauthorized")
		return t, NewErrorUnauthorized(err)
	}
	for _, c := range checks.Checks {
		if err = c(authCtx); err != nil {
			a.logger.With("error", err, "user", authCtx.UserID()).Log(ctx, slog.LevelWarn, "permission denied")
			return t, NewErrorPermissionDenied(err)
		}
	}
	authCtx.SetToken(token)
	return authCtx, nil
}

// Verifier defines the possible verification checks such as validation of the authorizationToken.
type Verifier[T Ctx] interface {
	CheckAuthorization(ctx context.Context, authorizationToken string) (T, error)
}

// VerifierInitializer abstracts the initialization of a [Verifier] by providing the ZITADEL domain, port and if tls is set
type VerifierInitializer[T Ctx] func(ctx context.Context, zitadel *zitadel.Zitadel) (Verifier[T], error)

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

// isServerError checks if an error indicates a 5xx server error from the introspection endpoint.
// It looks for 5xx status codes in the error message or common server error indicators.
func isServerError(err error) bool {
	if err == nil {
		return false
	}

	errorMsg := err.Error()

	// Check for explicit 5xx status codes in the error message
	statusCodeRegex := regexp.MustCompile(`\b(5\d{2})\b`)
	matches := statusCodeRegex.FindStringSubmatch(errorMsg)
	if len(matches) > 1 {
		if code, parseErr := strconv.Atoi(matches[1]); parseErr == nil {
			if code >= 500 && code < 600 {
				return true
			}
		}
	}

	// Check wrapped errors
	var unwrappedErr error = err
	for unwrappedErr != nil {
		if unwrappedMsg := unwrappedErr.Error(); unwrappedMsg != errorMsg {
			matches := statusCodeRegex.FindStringSubmatch(unwrappedMsg)
			if len(matches) > 1 {
				if code, parseErr := strconv.Atoi(matches[1]); parseErr == nil {
					if code >= 500 && code < 600 {
						return true
					}
				}
			}
		}
		unwrappedErr = errors.Unwrap(unwrappedErr)
	}

	return false
}
