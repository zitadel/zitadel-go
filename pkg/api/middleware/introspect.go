package middleware

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/caos/oidc/pkg/client/rs"
	"github.com/caos/oidc/pkg/oidc"
)

var (
	ErrMissingHeader = errors.New("auth header missing")
	ErrInvalidHeader = errors.New("invalid auth header")
	ErrInvalidToken  = errors.New("invalid token")
)

const (
	INTROSPECTION = "Introspection"
)

func WithCheckClaim(claim string, requiredValue interface{}) func(oidc.IntrospectionResponse) error {
	return func(response oidc.IntrospectionResponse) error {
		c := response.GetClaim(claim)
		if c == nil {
			return fmt.Errorf("%w: claim %s empty", ErrInvalidToken, claim)
		}
		if claim != requiredValue {
			return fmt.Errorf("%w: wrong value for claim %s", ErrInvalidToken, claim)
		}
		return nil
	}
}

//Introspect calls the OAuth2 Introspection endpoint and returns an error if token is not active
func Introspect(ctx context.Context, authHeader string, resourceServer rs.ResourceServer, opts ...func(oidc.IntrospectionResponse) error) (oidc.IntrospectionResponse, error) {
	if authHeader == "" {
		return nil, ErrMissingHeader
	}
	parts := strings.Split(authHeader, oidc.PrefixBearer)
	if len(parts) != 2 {
		return nil, ErrInvalidHeader
	}
	resp, err := rs.Introspect(ctx, resourceServer, parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	if !resp.IsActive() {
		return nil, ErrInvalidToken
	}
	for _, opt := range opts {
		if err := opt(resp); err != nil {
			return nil, err
		}
	}
	return resp, nil
}
