package middleware

import (
	"context"
	"errors"
	"strings"

	"github.com/zitadel/oidc/pkg/client/rs"
	"github.com/zitadel/oidc/pkg/oidc"
)

var (
	ErrMissingHeader = errors.New("auth header missing")
	ErrInvalidHeader = errors.New("invalid auth header")
	ErrInvalidToken  = errors.New("invalid token")
)

//Introspect calls the OAuth2 Introspection endpoint and returns an error if token is not active
func Introspect(ctx context.Context, authHeader string, resourceServer rs.ResourceServer) error {
	if authHeader == "" {
		return ErrMissingHeader
	}
	parts := strings.Split(authHeader, oidc.PrefixBearer)
	if len(parts) != 2 {
		return ErrInvalidHeader
	}
	resp, err := rs.Introspect(ctx, resourceServer, parts[1])
	if err != nil {
		return ErrInvalidToken
	}
	if !resp.IsActive() {
		return ErrInvalidToken
	}
	return nil
}
