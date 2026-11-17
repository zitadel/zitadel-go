package middleware

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/zitadel/zitadel-go/v3/pkg/client/internal/httpclient"
	"github.com/zitadel/zitadel-go/v3/pkg/client/internal/testidp"
)

func TestJWTProfileHelpers_UseTheContextHTTPClient(t *testing.T) {
	keyFile := testidp.KeyFileJSON(t)
	path := filepath.Join(t.TempDir(), "key.json")
	require.NoError(t, os.WriteFile(path, keyFile, 0o600))
	pem := testidp.PrivateKey(t)

	tests := []struct {
		name string
		// source creates the token source with the context the client is stored in.
		source func(ctx context.Context, issuer string) (oauth2.TokenSource, error)
	}{
		{
			name: "JWTProfileFromPath",
			source: func(ctx context.Context, issuer string) (oauth2.TokenSource, error) {
				return JWTProfileFromPath(ctx, path)(issuer, nil)
			},
		},
		{
			name: "JWTProfileFromFileData",
			source: func(ctx context.Context, issuer string) (oauth2.TokenSource, error) {
				return JWTProfileFromFileData(ctx, keyFile)(issuer, nil)
			},
		},
		{
			name: "JWTProfileFromKeyAndUserID",
			source: func(ctx context.Context, issuer string) (oauth2.TokenSource, error) {
				return JWTProfileFromKeyAndUserID(ctx, pem, "key", "user")(issuer, nil)
			},
		},
		{
			name: "JWTProfileFromPathContext",
			source: func(ctx context.Context, issuer string) (oauth2.TokenSource, error) {
				return JWTProfileFromPathContext(path)(ctx, issuer, nil)
			},
		},
		{
			name: "JWTProfileFromFileDataContext",
			source: func(ctx context.Context, issuer string) (oauth2.TokenSource, error) {
				return JWTProfileFromFileDataContext(keyFile)(ctx, issuer, nil)
			},
		},
		{
			name: "JWTProfileFromKeyAndUserIDContext",
			source: func(ctx context.Context, issuer string) (oauth2.TokenSource, error) {
				return JWTProfileFromKeyAndUserIDContext(pem, "key", "user")(ctx, issuer, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := testidp.New(t, false)
			ctx := httpclient.Configure(context.Background(), false, map[string]string{"x-foo": "bar"})

			ts, err := tt.source(ctx, idp.URL)
			require.NoError(t, err)
			_, err = ts.Token()
			require.NoError(t, err)

			assert.Equal(t, "bar", idp.Header(testidp.DiscoveryPath, "x-foo"))
			assert.Equal(t, "bar", idp.Header(testidp.TokenPath, "x-foo"))
		})
	}
}
