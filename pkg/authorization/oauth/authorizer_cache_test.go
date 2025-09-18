package oauth

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// testCache is an in-memory TTL cache used for unit tests.
type testCache[T any] struct {
	store map[string]cacheEntry[T]
	ttl   time.Duration
}

type cacheEntry[T any] struct {
	v         T
	expiresAt time.Time
}

func newTestCache[T any](ttl time.Duration) *testCache[T] {
	return &testCache[T]{store: make(map[string]cacheEntry[T]), ttl: ttl}
}

func (c *testCache[T]) Get(token string) (T, bool) {
	entry, ok := c.store[token]
	if !ok || time.Now().After(entry.expiresAt) {
		var zero T
		return zero, false
	}
	return entry.v, true
}

func (c *testCache[T]) Set(token string, value T, ttl time.Duration) {
	if ttl <= 0 {
		ttl = c.ttl
	}
	c.store[token] = cacheEntry[T]{v: value, expiresAt: time.Now().Add(ttl)}
}

// testIntrospectionResp mirrors the minimal fields we assert on.
type testIntrospectionResp struct {
	Active  bool   `json:"active,omitempty"`
	Subject string `json:"sub,omitempty"`
}

// mockResourceServerCache is a minimal rs.ResourceServer stand-in that provides
// a custom HttpClient and URL so rs.Introspect uses our mocked transport.
type mockResourceServerCache struct {
	client *http.Client
	url    string
}

func (m *mockResourceServerCache) IntrospectionURL() string { return m.url }
func (m *mockResourceServerCache) TokenEndpoint() string    { return "" }
func (m *mockResourceServerCache) HttpClient() *http.Client { return m.client }
func (m *mockResourceServerCache) AuthFn() (any, error)     { return nil, nil }

// mockHTTPTransportCache returns a fixed response and tracks call count.
type mockHTTPTransportCache struct {
	respBody []byte
	status   int
	calls    int
}

func (m *mockHTTPTransportCache) RoundTrip(_ *http.Request) (*http.Response, error) {
	m.calls++
	return &http.Response{
		StatusCode: m.status,
		Body:       io.NopCloser(bytes.NewReader(m.respBody)),
	}, nil
}

func TestIntrospectionVerificationWithCache_CheckAuthorization(t *testing.T) {
	mt := &mockHTTPTransportCache{
		respBody: []byte(`{"active": true, "sub": "sub1"}`),
		status:   200,
	}
	rsrv := &mockResourceServerCache{
		client: &http.Client{Transport: mt},
		url:    "https://example.test/introspect",
	}
	cache := newTestCache[*testIntrospectionResp](time.Minute)

	v := NewIntrospectionVerificationWithCache[*testIntrospectionResp](rsrv, cache, 30*time.Second)

	t.Run("first call performs introspection and caches", func(t *testing.T) {
		out, err := v.CheckAuthorization(context.Background(), "Bearer token1")
		assert.NoError(t, err)
		assert.True(t, out.Active)
		assert.Equal(t, "sub1", out.Subject)
		assert.Equal(t, 1, mt.calls)

		cached, ok := cache.Get("token1")
		assert.True(t, ok)
		assert.True(t, cached.Active)
		assert.Equal(t, "sub1", cached.Subject)
	})

	t.Run("second call uses cache (no extra HTTP call)", func(t *testing.T) {
		out, err := v.CheckAuthorization(context.Background(), "Bearer token1")
		assert.NoError(t, err)
		assert.True(t, out.Active)
		assert.Equal(t, "sub1", out.Subject)
		assert.Equal(t, 1, mt.calls)
	})

	t.Run("different token performs another HTTP call", func(t *testing.T) {
		out, err := v.CheckAuthorization(context.Background(), "Bearer token2")
		assert.NoError(t, err)
		assert.True(t, out.Active)
		assert.Equal(t, "sub1", out.Subject)
		assert.Equal(t, 2, mt.calls)

		_, ok := cache.Get("token2")
		assert.True(t, ok)
	})
}
