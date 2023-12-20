package oauth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rs"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	ErrInvalidAuthorizationHeader = errors.New("invalid authorization header, must be prefixed with `Bearer`")
	ErrIntrospectionFailed        = errors.New("token introspection failed")
)

// IntrospectionVerification provides an [authorization.Verifier] implementation
// by validating the provided token with an OAuth2 Introspection call.
// Use [WithIntrospection] for implementation.
type IntrospectionVerification[T any] struct {
	rs.ResourceServer
}

// WithIntrospection creates the OAuth2 Introspection implementation of the [authorization.Verifier] interface.
// The introspection endpoint itself requires some [IntrospectionAuthentication] of the client.
// Possible implementation are [JWTProfileIntrospectionAuthentication] and [ClientIDSecretIntrospectionAuthentication].
func WithIntrospection[T authorization.Ctx](auth IntrospectionAuthentication) authorization.VerifierInitializer[T] {
	return func(ctx context.Context, zitadel *zitadel.Zitadel) (authorization.Verifier[T], error) {
		resourceServer, err := auth(ctx, zitadel.Origin())
		if err != nil {
			return nil, err
		}
		return &IntrospectionVerification[T]{
			ResourceServer: resourceServer,
		}, nil
	}
}

type IntrospectionAuthentication func(ctx context.Context, issuer string) (rs.ResourceServer, error)

// JWTProfileIntrospectionAuthentication allows to authenticate the introspection request with JWT Profile
// using a key.json provided by ZITADEL.
func JWTProfileIntrospectionAuthentication(file *client.KeyFile) IntrospectionAuthentication {
	return func(ctx context.Context, issuer string) (rs.ResourceServer, error) {
		return rs.NewResourceServerJWTProfile(ctx, issuer, file.ClientID, file.KeyID, []byte(file.Key))
	}
}

// ClientIDSecretIntrospectionAuthentication allows to authenticate the introspection request with
// the client_id and client_secret provided by ZITADEL.
func ClientIDSecretIntrospectionAuthentication(clientID, clientSecret string) IntrospectionAuthentication {
	return func(ctx context.Context, issuer string) (rs.ResourceServer, error) {
		return rs.NewResourceServerClientCredentials(ctx, issuer, clientID, clientSecret)
	}
}

// DefaultAuthorization is a short version of [WithIntrospection[*IntrospectionContext](JWTProfileIntrospectionAuthentication)]
// with a key.json read from a provided path.
func DefaultAuthorization(path string) authorization.VerifierInitializer[*IntrospectionContext] {
	c, err := client.ConfigFromKeyFile(path)
	if err != nil {
		return func(ctx context.Context, _ *zitadel.Zitadel) (authorization.Verifier[*IntrospectionContext], error) {
			return nil, err
		}
	}
	return WithIntrospection[*IntrospectionContext](JWTProfileIntrospectionAuthentication(c))
}

// CheckAuthorization implements the [authorization.Verifier] interface by checking the authorizationToken
// on the OAuth2 introspection endpoint.
// On success, it will return a generic struct of type [T] of the [IntrospectionVerification].
func (i *IntrospectionVerification[T]) CheckAuthorization(ctx context.Context, authorizationToken string) (resp T, err error) {
	accessToken, ok := strings.CutPrefix(authorizationToken, oidc.BearerToken)
	if !ok {
		return resp, ErrInvalidAuthorizationHeader
	}
	resp, err = rs.Introspect[T](ctx, i.ResourceServer, strings.TrimSpace(accessToken))
	if err != nil {
		return resp, fmt.Errorf("%w: %v", ErrIntrospectionFailed, err)
	}
	return resp, nil
}
