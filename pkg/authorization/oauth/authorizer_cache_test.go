package oauth

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCache is a minimal, non-thread-safe TTL cache designed specifically for
// synchronous, single-goroutine unit tests.
type testCache[T any] struct {
	store map[string]cacheEntry[T]
	ttl   time.Duration
}

// cacheEntry stores a value along with its expiration time.
type cacheEntry[T any] struct {
	v         T
	expiresAt time.Time
}

// newTestCache creates and returns a new instance of a testCache.
func newTestCache[T any](ttl time.Duration) *testCache[T] {
	return &testCache[T]{store: make(map[string]cacheEntry[T]), ttl: ttl}
}

// Get retrieves a value from the cache if it exists and has not expired.
func (c *testCache[T]) Get(token string) (T, bool) {
	entry, ok := c.store[token]
	if !ok || time.Now().After(entry.expiresAt) {
		var zero T
		return zero, false
	}
	return entry.v, true
}

// Set adds a value to the cache with a specified TTL.
func (c *testCache[T]) Set(token string, value T, ttl time.Duration) {
	c.store[token] = cacheEntry[T]{v: value, expiresAt: time.Now().Add(ttl)}
}

// testIntrospectionResp is a mock response struct for introspection, mirroring
// the minimal fields needed for test assertions.
type testIntrospectionResp struct {
	Active  bool   `json:"active,omitempty"`
	Subject string `json:"sub,omitempty"`
}

// mockResourceServerCache is a mock implementation of the rs.ResourceServer
// interface used for testing the caching authorizer.
type mockResourceServerCache struct {
	client *http.Client
	url    string
}

func (m *mockResourceServerCache) IntrospectionURL() string { return m.url }
func (m *mockResourceServerCache) TokenEndpoint() string    { return "" }
func (m *mockResourceServerCache) HttpClient() *http.Client { return m.client }
func (m *mockResourceServerCache) AuthFn() (any, error)     { return nil, nil }

// mockHTTPTransportCache is a mock http.RoundTripper that returns a canned
// response and tracks the number of calls made.
type mockHTTPTransportCache struct {
	respBody []byte
	status   int
	calls    int
}

// RoundTrip increments the call counter and returns a fixed HTTP response.
func (m *mockHTTPTransportCache) RoundTrip(_ *http.Request) (*http.Response, error) {
	m.calls++
	return &http.Response{
		StatusCode: m.status,
		Body:       io.NopCloser(bytes.NewReader(m.respBody)),
	}, nil
}

// TestIntrospectionVerificationWithCache_CheckAuthorization verifies the caching
// behavior of the CheckAuthorization method using a table-driven approach to
// ensure test cases are fully isolated and prevent state leakage.
func TestIntrospectionVerificationWithCache_CheckAuthorization(t *testing.T) {
	mockRespBody := []byte(`{"active": true, "sub": "sub-from-http"}`)

	testCases := []struct {
		name              string
		token             string
		setupCache        func(c *testCache[*testIntrospectionResp])
		expectedSubject   string
		expectedHTTPCalls int
	}{
		{
			name:              "token is not in cache",
			token:             "Bearer new-token",
			setupCache:        func(c *testCache[*testIntrospectionResp]) {},
			expectedSubject:   "sub-from-http",
			expectedHTTPCalls: 1,
		},
		{
			name:  "token is found in cache and not expired",
			token: "Bearer cached-token",
			setupCache: func(c *testCache[*testIntrospectionResp]) {
				resp := &testIntrospectionResp{Active: true, Subject: "sub-from-cache"}
				c.Set("cached-token", resp, time.Minute)
			},
			expectedSubject:   "sub-from-cache",
			expectedHTTPCalls: 0,
		},
		{
			name:  "token is found in cache but is expired",
			token: "Bearer expired-token",
			setupCache: func(c *testCache[*testIntrospectionResp]) {
				resp := &testIntrospectionResp{Active: true, Subject: "sub-from-cache"}
				c.Set("expired-token", resp, -1*time.Minute)
			},
			expectedSubject:   "sub-from-http",
			expectedHTTPCalls: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockTransport := &mockHTTPTransportCache{
				respBody: mockRespBody,
				status:   200,
			}
			resourceServer := &mockResourceServerCache{
				client: &http.Client{Transport: mockTransport},
				url:    "https://example.test/introspect",
			}
			cache := newTestCache[*testIntrospectionResp](time.Minute)
			tc.setupCache(cache)

			verifier := NewIntrospectionVerificationWithCache[*testIntrospectionResp](resourceServer, cache, 30*time.Second)

			out, err := verifier.CheckAuthorization(context.Background(), tc.token)

			require.NoError(t, err)
			assert.Equal(t, tc.expectedSubject, out.Subject)
			assert.Equal(t, tc.expectedHTTPCalls, mockTransport.calls)
		})
	}
}
