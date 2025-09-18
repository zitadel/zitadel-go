package oauth

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// exCache is a minimal TTL cache used in the example.
type exCache[T any] struct {
	data map[string]struct {
		v   T
		exp time.Time
	}
	ttl time.Duration
}

func newExCache[T any](ttl time.Duration) *exCache[T] {
	return &exCache[T]{data: make(map[string]struct {
		v   T
		exp time.Time
	}), ttl: ttl}
}

func (c *exCache[T]) Get(key string) (T, bool) {
	e, ok := c.data[key]
	if !ok || time.Now().After(e.exp) {
		var zero T
		return zero, false
	}
	return e.v, true
}

func (c *exCache[T]) Set(key string, val T, ttl time.Duration) {
	if ttl <= 0 {
		ttl = c.ttl
	}
	c.data[key] = struct {
		v   T
		exp time.Time
	}{v: val, exp: time.Now().Add(ttl)}
}

// exRS is a minimal ResourceServer stand-in for the example.
type exRS struct {
	client *http.Client
	url    string
}

func (e *exRS) IntrospectionURL() string { return e.url }
func (e *exRS) TokenEndpoint() string    { return "" }
func (e *exRS) HttpClient() *http.Client { return e.client }
func (e *exRS) AuthFn() (any, error)     { return nil, nil }

// exTransport returns a canned introspection response.
type exTransport struct{}

func (t *exTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	body := []byte(`{"active": true, "sub": "alice"}`)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, nil
}

// ExampleIntrospectionVerificationWithCache shows a cached introspection flow.
func ExampleIntrospectionVerificationWithCache() {
	rsrv := &exRS{
		client: &http.Client{Transport: &exTransport{}},
		url:    "https://example.test/introspect",
	}

	cache := newExCache[struct {
		Active  bool   `json:"active"`
		Subject string `json:"sub"`
	}](30 * time.Second)

	v := NewIntrospectionVerificationWithCache(rsrv, cache, 30*time.Second)

	resp, err := v.CheckAuthorization(context.Background(), "Bearer token123")
	if err != nil {
		panic(err)
	}
	fmt.Println(resp.Subject)
	// Output: alice
}
