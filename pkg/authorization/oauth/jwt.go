package oauth

import (
	"context"
	"errors"
	"fmt"
	gohttp "net/http"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	ErrInvalidToken = errors.New("invalid token")
)

// JWTVerification provides an [authorization.Verifier] implementation
// by validating an Authorization header bearing a JWT locally.
type JWTVerification struct {
	verifier *op.AccessTokenVerifier
}

// WithJWT creates the local JWT validation implementation of the
// [authorization.Verifier] interface. It is the recommended high-performance
// method for securing high-throughput APIs.
//
// This initializer uses OIDC Discovery to dynamically find the JWKS URI and
// creates an [rp.RemoteKeySet] which fetches and caches the keys in memory.
// It accepts the clientID for audience validation and optional
// [op.AccessTokenVerifierOpt] to allow for supported a different signing algorithm.
// validation, such as setting a clock skew tolerance.
func WithJWT(clientID string, httpClient *gohttp.Client, options ...op.AccessTokenVerifierOpt) authorization.VerifierInitializer[*IntrospectionContext] {
	if httpClient == nil {
		httpClient = gohttp.DefaultClient
	}

	return func(ctx context.Context, zitadel *zitadel.Zitadel) (authorization.Verifier[*IntrospectionContext], error) {
		discoveryConfig, err := client.Discover(ctx, zitadel.Origin(), httpClient)
		if err != nil {
			return nil, fmt.Errorf("OIDC discovery failed: %w", err)
		}

		keySet := rp.NewRemoteKeySet(httpClient, discoveryConfig.JwksURI)

		verifier := op.NewAccessTokenVerifier(discoveryConfig.Issuer, keySet, options...)

		return &JWTVerification{
			verifier: verifier,
		}, nil
	}
}

// CheckAuthorization implements the [authorization.Verifier] interface. It
// validates an access token from an "Authorization: Bearer <token>" header.
//
// The validation is performed locally using the cached JWKS keys. It checks
// the token's signature, expiry, and issuer. On success, it returns an
// [*IntrospectionContext] populated with the claims from the validated JWT.
// This provides a fast, offline alternative to token introspection.
func (j *JWTVerification) CheckAuthorization(ctx context.Context, authorizationToken string) (*IntrospectionContext, error) {
	accessToken, ok := strings.CutPrefix(authorizationToken, oidc.BearerToken)
	if !ok {
		return nil, ErrInvalidAuthorizationHeader
	}
	accessToken = strings.TrimSpace(accessToken)

	claims, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](ctx, accessToken, j.verifier)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if len(claims.Audience) == 0 {
		return nil, fmt.Errorf("%w: empty aud", ErrInvalidToken)
	}

	resp := &IntrospectionContext{
		IntrospectionResponse: oidc.IntrospectionResponse{
			Active:     true,
			Issuer:     claims.Issuer,
			Subject:    claims.Subject,
			Audience:   claims.Audience,
			Expiration: claims.Expiration,
			IssuedAt:   claims.IssuedAt,
			NotBefore:  claims.NotBefore,
			ClientID:   claims.ClientID,
			JWTID:      claims.JWTID,
			Claims:     claims.Claims,
		},
	}
	resp.SetToken(accessToken)
	return resp, nil
}

// DefaultJWTAuthorization provides a simple initializer for the recommended
// high-performance JWT validation method. It is a convenient wrapper around
// WithJWT.
//
// It takes the clientID of the protected resource server and optional
// [rp.VerifierOption] to customize the validation behavior.
func DefaultJWTAuthorization(clientID string, options ...rp.VerifierOption) authorization.VerifierInitializer[*IntrospectionContext] {
	return WithJWT(clientID, nil, options...)
}
