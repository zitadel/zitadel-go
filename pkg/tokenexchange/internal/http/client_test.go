package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

type customRoundTripper struct{}

func (c *customRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return http.DefaultTransport.RoundTrip(req)
}

func TestNewClient(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		z := zitadel.New("example.zitadel.cloud")
		client := NewClient(z)
		assert.NotNil(t, client)
		assert.NotNil(t, client.Transport)
		assert.Equal(t, 30*time.Second, client.Timeout)
	})

	t.Run("insecure skip verify", func(t *testing.T) {
		z := zitadel.New("example.zitadel.cloud",
			zitadel.WithInsecureSkipVerifyTLS(),
		)
		client := NewClient(z)
		assert.NotNil(t, client)

		transport, ok := client.Transport.(*http.Transport)
		require.True(t, ok)
		assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
	})

	t.Run("custom headers", func(t *testing.T) {
		z := zitadel.New("example.zitadel.cloud",
			zitadel.WithTransportHeader("X-Custom", "value"),
		)
		client := NewClient(z)
		assert.NotNil(t, client)

		_, ok := client.Transport.(*headerRoundTripper)
		assert.True(t, ok)
	})

	t.Run("insecure and custom headers", func(t *testing.T) {
		z := zitadel.New("example.zitadel.cloud",
			zitadel.WithInsecureSkipVerifyTLS(),
			zitadel.WithTransportHeader("X-Custom", "value"),
		)
		client := NewClient(z)
		assert.NotNil(t, client)

		hrt, ok := client.Transport.(*headerRoundTripper)
		require.True(t, ok)
		assert.Equal(t, "value", hrt.headers["X-Custom"])
	})

	t.Run("fallback when DefaultTransport is overridden", func(t *testing.T) {
		original := http.DefaultTransport
		http.DefaultTransport = &customRoundTripper{}
		defer func() { http.DefaultTransport = original }()

		z := zitadel.New("example.zitadel.cloud")
		client := NewClient(z)
		assert.NotNil(t, client)
		assert.NotNil(t, client.Transport)
		assert.Equal(t, 30*time.Second, client.Timeout)

		_, ok := client.Transport.(*http.Transport)
		assert.True(t, ok)
	})

	t.Run("fallback when DefaultTransport is nil", func(t *testing.T) {
		original := http.DefaultTransport
		http.DefaultTransport = nil
		defer func() { http.DefaultTransport = original }()

		z := zitadel.New("example.zitadel.cloud")
		client := NewClient(z)
		assert.NotNil(t, client)
		assert.NotNil(t, client.Transport)
		assert.Equal(t, 30*time.Second, client.Timeout)
	})
}

func TestHeaderRoundTripper(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "value1", r.Header.Get("X-Header-1"))
		assert.Equal(t, "value2", r.Header.Get("X-Header-2"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	roundTripper := &headerRoundTripper{
		base: http.DefaultTransport,
		headers: map[string]string{
			"X-Header-1": "value1",
			"X-Header-2": "value2",
		},
	}

	client := &http.Client{Transport: roundTripper}
	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
