package oauth

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/patrickmn/go-cache"
)

// GoCacheAdapter provides a concrete, thread-safe implementation of the
// TokenCache interface by wrapping the popular patrickmn/go-cache library.
// It acts as a bridge, allowing the external library to be used as a
// pluggable component in the verification process.
type GoCacheAdapter[T any] struct {
	client *cache.Cache
}

// NewGoCacheAdapter creates a new adapter that uses patrickmn/go-cache as its
// underlying storage. The parameters control the cache's eviction policy.
func NewGoCacheAdapter[T any](defaultExpiration, cleanupInterval time.Duration) *GoCacheAdapter[T] {
	return &GoCacheAdapter[T]{
		client: cache.New(defaultExpiration, cleanupInterval),
	}
}

// Get retrieves a value from the cache. It satisfies the TokenCache interface
// by fetching the item from the underlying cache and performing a safe type
// assertion to the expected generic type.
func (a *GoCacheAdapter[T]) Get(token string) (T, bool) {
	var zero T
	value, found := a.client.Get(token)
	if !found {
		return zero, false
	}

	typedValue, ok := value.(T)
	if !ok {
		return zero, false
	}
	return typedValue, true
}

// Set stores a value in the cache. It satisfies the TokenCache interface by
// passing the token, value, and TTL directly to the underlying cache instance.
func (a *GoCacheAdapter[T]) Set(token string, value T, ttl time.Duration) {
	a.client.Set(token, value, ttl)
}

// exRS is a minimal ResourceServer stand-in used for this example. It provides
// the necessary methods to satisfy the rs.ResourceServer interface.
type exRS struct {
	client *http.Client
	url    string
}

// IntrospectionURL returns the mock introspection endpoint URL.
func (e *exRS) IntrospectionURL() string {
	return e.url
}

// TokenEndpoint returns an empty string as it's not needed for this example.
func (e *exRS) TokenEndpoint() string {
	return ""
}

// HttpClient returns the mock HTTP client.
func (e *exRS) HttpClient() *http.Client {
	return e.client
}

// AuthFn returns nil as it's not needed for this example.
func (e *exRS) AuthFn() (any, error) {
	return nil, nil
}

// exTransport is a mock http.RoundTripper that returns a canned introspection
// response without making a real network call.
type exTransport struct{}

// RoundTrip returns a fixed, successful introspection response.
func (t *exTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	body := []byte(`{"active": true, "sub": "alice"}`)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, nil
}

// ExampleIntrospectionVerificationWithCache demonstrates a complete verification
// flow using a production-ready cache. It constructs a mock resource server and
// a GoCacheAdapter, injects them into a new verifier instance, and then
// executes an authorization check to show the components working together.
func ExampleIntrospectionVerificationWithCache() {
	mockTransport := &exTransport{}
	httpClient := &http.Client{
		Transport: mockTransport,
	}

	resourceServer := &exRS{
		client: httpClient,
		url:    "https://example.test/introspect",
	}

	type introspectionResp struct {
		Active  bool   `json:"active"`
		Subject string `json:"sub"`
	}

	cacheAdapter := NewGoCacheAdapter[introspectionResp](
		5*time.Minute,
		10*time.Minute,
	)

	verifier := NewIntrospectionVerificationWithCache(
		resourceServer,
		cacheAdapter,
		30*time.Second,
	)

	resp, err := verifier.CheckAuthorization(context.Background(), "Bearer token123")
	if err != nil {
		panic(err)
	}

	fmt.Println(resp.Subject)
	// Output: alice
}
