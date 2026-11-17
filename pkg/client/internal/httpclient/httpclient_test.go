package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/zitadel/zitadel-go/v3/pkg/client/internal/testidp"
)

func TestConfigure_NothingRequested_ReturnsTheSameContext(t *testing.T) {
	ctx := context.Background()

	assert.Equal(t, ctx, Configure(ctx, false, nil))
	assert.Equal(t, ctx, Configure(ctx, false, map[string]string{}))
	assert.Nil(t, FromContext(Configure(ctx, false, nil)))
}

func TestConfigure_AddsHeadersToEveryRequest(t *testing.T) {
	idp := testidp.New(t, false)

	resp, err := FromContext(Configure(context.Background(), false, map[string]string{"x-foo": "bar"})).Get(idp.URL + "/anything")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, "bar", idp.Header("/anything", "x-foo"))
}

func TestConfigure_CopiesTheHeaders(t *testing.T) {
	idp := testidp.New(t, false)
	headers := map[string]string{"x-foo": "bar"}
	c := FromContext(Configure(context.Background(), false, headers))
	headers["x-foo"] = "changed"
	headers["x-late"] = "added"

	resp, err := c.Get(idp.URL + "/anything")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, "bar", idp.Header("/anything", "x-foo"))
	assert.Empty(t, idp.Header("/anything", "x-late"))
}

func TestConfigure_SkipsCertificateVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	_, err := FromContext(Configure(context.Background(), false, map[string]string{"x-foo": "bar"})).Get(srv.URL)
	assert.Error(t, err, "a self-signed certificate must be rejected unless skipping is requested")

	resp, err := FromContext(Configure(context.Background(), true, nil)).Get(srv.URL)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
}

func TestConfigure_KeepsTheInjectedClient(t *testing.T) {
	idp := testidp.New(t, true)
	injected := idp.Client()
	injected.Timeout = 7 * time.Second
	original := injected.Transport
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, injected)

	configured := FromContext(Configure(ctx, false, map[string]string{"x-foo": "bar"}))

	resp, err := configured.Get(idp.URL + "/anything")
	require.NoError(t, err, "the certificates trusted by the injected client must still be trusted")
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, "bar", idp.Header("/anything", "x-foo"))
	assert.Equal(t, 7*time.Second, configured.Timeout)
	assert.Same(t, original, injected.Transport, "the injected client must not be modified")
	assert.Same(t, injected, FromContext(ctx))
}

type markingTransport struct {
	base http.RoundTripper
}

func (m markingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("x-wrapped", "yes")
	return m.base.RoundTrip(req)
}

func TestConfigure_WrapsAReplacedDefaultTransport(t *testing.T) {
	original := http.DefaultTransport
	http.DefaultTransport = markingTransport{base: original}
	t.Cleanup(func() { http.DefaultTransport = original })
	idp := testidp.New(t, false)

	resp, err := FromContext(Configure(context.Background(), false, map[string]string{"x-foo": "bar"})).Get(idp.URL + "/anything")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, "bar", idp.Header("/anything", "x-foo"))
	assert.Equal(t, "yes", idp.Header("/anything", "x-wrapped"), "the replaced default transport must stay in use")
}

func TestConfigure_SkipVerifyWithAReplacedDefaultTransport(t *testing.T) {
	original := http.DefaultTransport
	http.DefaultTransport = markingTransport{base: original}
	t.Cleanup(func() { http.DefaultTransport = original })
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	c := FromContext(Configure(context.Background(), true, nil))

	resp, err := c.Get(srv.URL)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
}

func TestFromContext(t *testing.T) {
	assert.Nil(t, FromContext(context.Background()))
	assert.Same(t, http.DefaultClient, OrDefault(context.Background()))

	c := &http.Client{}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, c)
	assert.Same(t, c, FromContext(ctx))
	assert.Same(t, c, OrDefault(ctx))

	assert.Nil(t, FromContext(context.WithValue(context.Background(), oauth2.HTTPClient, "not a client")))
}

func TestJWTProfileTokenSource(t *testing.T) {
	tests := []struct {
		name       string
		withClient bool
		expect     string
	}{
		{name: "uses the context client for discovery and token", withClient: true, expect: "bar"},
		{name: "uses the default client without one", withClient: false, expect: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := testidp.New(t, false)
			ctx := context.Background()
			if tt.withClient {
				ctx = Configure(ctx, false, map[string]string{"x-foo": "bar"})
			}

			ts, err := JWTProfileTokenSource(ctx, idp.URL, "user", "key", testidp.PrivateKey(t), nil)
			require.NoError(t, err)
			_, err = ts.Token()
			require.NoError(t, err)

			assert.Equal(t, tt.expect, idp.Header(testidp.DiscoveryPath, "x-foo"))
			assert.Equal(t, tt.expect, idp.Header(testidp.TokenPath, "x-foo"))
		})
	}
}

type closeTrackingTransport struct {
	*http.Transport
	closed *bool
}

func (c closeTrackingTransport) CloseIdleConnections() {
	*c.closed = true
	c.Transport.CloseIdleConnections()
}

func TestConfigure_ForwardsCloseIdleConnections(t *testing.T) {
	closed := false
	injected := &http.Client{Transport: closeTrackingTransport{Transport: http.DefaultTransport.(*http.Transport).Clone(), closed: &closed}}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, injected)

	FromContext(Configure(ctx, false, map[string]string{"x-foo": "bar"})).CloseIdleConnections()

	assert.True(t, closed)
}
