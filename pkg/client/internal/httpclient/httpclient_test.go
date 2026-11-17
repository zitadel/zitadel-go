package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel-go/v3/pkg/client/internal/testidp"
)

func TestNew_NothingRequested_ReturnsNil(t *testing.T) {
	assert.Nil(t, New(false, nil))
	assert.Nil(t, New(false, map[string]string{}))
}

func TestNew_AddsHeadersToEveryRequest(t *testing.T) {
	idp := testidp.New(t, false)

	resp, err := New(false, map[string]string{"x-foo": "bar"}).Get(idp.URL + "/anything")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, "bar", idp.Header("/anything", "x-foo"))
}

func TestNew_SkipsCertificateVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	_, err := New(false, map[string]string{"x-foo": "bar"}).Get(srv.URL)
	assert.Error(t, err, "a self-signed certificate must be rejected unless skipping is requested")

	resp, err := New(true, nil).Get(srv.URL)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
}

func TestFromContext(t *testing.T) {
	assert.Nil(t, FromContext(context.Background()))
	assert.Same(t, http.DefaultClient, OrDefault(context.Background()))

	c := &http.Client{}
	ctx := WithContext(context.Background(), c)
	assert.Same(t, c, FromContext(ctx))
	assert.Same(t, c, OrDefault(ctx))

	assert.Nil(t, FromContext(WithContext(context.Background(), nil)))
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
				ctx = WithContext(ctx, New(false, map[string]string{"x-foo": "bar"}))
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
