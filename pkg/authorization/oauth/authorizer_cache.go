package oauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rs"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// TokenCache defines a minimal interface for caching introspection results.
// Implementations must be safe for concurrent use. The TTL informs the cache
// how long the entry should remain valid before eviction.
type TokenCache[T any] interface {
	// Get returns the cached value for token, if present and not expired.
	// If not present or expired, ok is false and the zero value is returned.
	Get(token string) (v T, ok bool)

	// Set stores value for token with the provided TTL. Implementations
	// should ensure expiry after the TTL elapses.
	Set(token string, value T, ttl time.Duration)
}

// IntrospectionVerificationWithCache validates bearer tokens using the OAuth2
// introspection endpoint and optionally caches the result to avoid repeated
// network calls for identical tokens within a configured TTL. If cache is nil,
// all calls hit the introspection endpoint.
type IntrospectionVerificationWithCache[T any] struct {
	rs    rs.ResourceServer
	cache TokenCache[T]
	ttl   time.Duration
}

// NewIntrospectionVerificationWithCache constructs a verifier that uses the
// provided ResourceServer for introspection and an optional cache for reusing
// results for the specified TTL. If cache is nil, no caching occurs.
func NewIntrospectionVerificationWithCache[T any](
	rs rs.ResourceServer,
	cache TokenCache[T],
	ttl time.Duration,
) *IntrospectionVerificationWithCache[T] {
	return &IntrospectionVerificationWithCache[T]{
		rs:    rs,
		cache: cache,
		ttl:   ttl,
	}
}

// CheckAuthorization validates authorizationToken. The value must be prefixed
// with "Bearer ". When a cache is configured, a cached result is returned if
// available; otherwise the introspection endpoint is called and the response
// is stored in the cache for the configured TTL.
func (v *IntrospectionVerificationWithCache[T]) CheckAuthorization(
	ctx context.Context,
	authorizationToken string,
) (resp T, err error) {
	var zero T

	token, ok := strings.CutPrefix(authorizationToken, oidc.BearerToken)
	if !ok {
		return zero, ErrInvalidAuthorizationHeader
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return zero, ErrInvalidAuthorizationHeader
	}

	if v.cache != nil {
		if cached, found := v.cache.Get(token); found {
			return cached, nil
		}
	}

	resp, err = rs.Introspect[T](ctx, v.rs, token)
	if err != nil {
		return zero, fmt.Errorf("%w: %v", ErrIntrospectionFailed, err)
	}

	if v.cache != nil {
		v.cache.Set(token, resp, v.ttl)
	}
	return resp, nil
}
