package oauth_test

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/zitadel-go/v3/pkg/authorization/oauth"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

//goland:noinspection HttpUrlsUsage
func TestWithJWT_Success(t *testing.T) {
	keyPair, err := NewTestKey(2048)
	require.NoError(t, err, "failed to generate rsa key")

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//goland:noinspection HttpUrlsUsage
		if r.URL.Path == "/keys" {
			jwks := map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"kty": "RSA",
						"kid": keyPair.KID(),
						"use": "sig",
						"n":   keyPair.ModulusString(),
						"e":   keyPair.ExponentString(),
					},
				},
			}
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
		} else {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(mockServer.Close)

	parsedURL, err := url.Parse(mockServer.URL)
	require.NoError(t, err, "failed to parse mock server url")

	z := zitadel.New(parsedURL.Hostname(), zitadel.WithInsecure(parsedURL.Port()))
	authorizer, err := authorization.New(context.Background(), z, oauth.DefaultJWTAuthorization("test-client-id"))
	require.NoError(t, err, "authorization.New with WithJWT failed")

	signedToken, err := signTestJWT(signParams{
		KeyID:      keyPair.KID(),
		PrivateKey: keyPair.Private(),
		Issuer:     mockServer.URL,
		Subject:    "test-user-id",
		Audience:   []string{"test-client-id"},
		TTL:        time.Hour,
	})
	require.NoError(t, err, "failed to create test JWT")

	authCtx, err := authorizer.CheckAuthorization(context.Background(), "Bearer "+signedToken)
	assert.NoError(t, err, "CheckAuthorization failed unexpectedly")

	if assert.NotNil(t, authCtx) {
		assert.Equal(t, "test-user-id", authCtx.UserID(), "UserID in context should match token subject")
		assert.True(t, authCtx.IsAuthorized(), "IsAuthorized should be true for a valid token")
	}
}
