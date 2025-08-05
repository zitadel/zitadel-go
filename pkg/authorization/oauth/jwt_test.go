package oauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
	"github.com/zitadel/zitadel-go/v3/pkg/authorization/oauth"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

//goland:noinspection HttpUrlsUsage
func TestWithJWT(t *testing.T) {
	keyPair, err := NewTestKey(2048)
	require.NoError(t, err, "failed to generate rsa key")

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/keys" {
			jwks := map[string]interface{}{"keys": []map[string]interface{}{{
				"kty": "RSA", "kid": keyPair.KID(), "use": "sig",
				"n": keyPair.ModulusString(), "e": keyPair.ExponentString(),
			}}}
			if err := json.NewEncoder(w).Encode(jwks); err != nil {
				http.Error(w, "failed to encode jwks", http.StatusInternalServerError)
			}
			return
		}
		if r.URL.Path == "/.well-known/openid-configuration" {
			discoveryDoc := map[string]interface{}{
				"issuer":   "http://" + r.Host,
				"jwks_uri": "http://" + r.Host + "/keys",
			}
			if err := json.NewEncoder(w).Encode(discoveryDoc); err != nil {
				http.Error(w, "failed to encode discovery doc", http.StatusInternalServerError)
			}
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(mockServer.Close)

	parsedURL, err := url.Parse(mockServer.URL)
	require.NoError(t, err, "failed to parse mock server url")

	z := zitadel.New(parsedURL.Hostname(), zitadel.WithInsecure(parsedURL.Port()))
	authorizer, err := authorization.New(context.Background(), z, oauth.DefaultJWTAuthorization("test-client-id"))
	require.NoError(t, err, "authorization.New with WithJWT failed")

	testCases := []struct {
		name          string
		ttl           time.Duration
		expectSuccess bool
	}{
		{
			name:          "Success: valid token",
			ttl:           time.Hour,
			expectSuccess: true,
		},
		{
			name:          "Failure: expired token",
			ttl:           -time.Hour,
			expectSuccess: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signedToken, err := signTestJWT(signParams{
				KeyID:      keyPair.KID(),
				PrivateKey: keyPair.Private(),
				Issuer:     mockServer.URL,
				Subject:    "test-user-id",
				Audience:   []string{"test-client-id"},
				TTL:        tc.ttl,
			})
			require.NoError(t, err, "failed to create test JWT")

			authCtx, err := authorizer.CheckAuthorization(context.Background(), "Bearer "+signedToken)

			if tc.expectSuccess {
				assert.NoError(t, err, "CheckAuthorization failed unexpectedly")
				if assert.NotNil(t, authCtx) {
					assert.Equal(t, "test-user-id", authCtx.UserID())
					assert.True(t, authCtx.IsAuthorized())
				}
			} else {
				assert.Error(t, err, "CheckAuthorization should have failed but didn't")
				assert.Nil(t, authCtx, "Context should be nil on failure")
			}
		})
	}
}
