package tokenexchange

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

func TestSubjectTokenTypeOptions(t *testing.T) {
	tests := []struct {
		name     string
		option   Option
		expected oidc.TokenType
	}{
		{
			name:     "SubjectIsUserID",
			option:   SubjectIsUserID(),
			expected: UserIDTokenType,
		},
		{
			name:     "SubjectIsAccessToken",
			option:   SubjectIsAccessToken(),
			expected: oidc.AccessTokenType,
		},
		{
			name:     "SubjectIsIDToken",
			option:   SubjectIsIDToken(),
			expected: oidc.IDTokenType,
		},
		{
			name:     "SubjectIsJWT",
			option:   SubjectIsJWT(),
			expected: oidc.JWTTokenType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config{}
			tt.option(cfg)
			assert.Equal(t, tt.expected, cfg.subjectTokenType)
		})
	}
}

func TestActorTokenTypeOptions(t *testing.T) {
	tests := []struct {
		name     string
		option   Option
		expected oidc.TokenType
	}{
		{
			name:     "ActorIsAccessToken",
			option:   ActorIsAccessToken(),
			expected: oidc.AccessTokenType,
		},
		{
			name:     "ActorIsIDToken",
			option:   ActorIsIDToken(),
			expected: oidc.IDTokenType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config{}
			tt.option(cfg)
			assert.Equal(t, tt.expected, cfg.actorTokenType)
		})
	}
}

func TestRequestOptions(t *testing.T) {
	t.Run("WithScopes", func(t *testing.T) {
		cfg := &config{}
		WithScopes("openid", "profile", "email")(cfg)
		assert.Equal(t, []string{"openid", "profile", "email"}, cfg.scopes)
	})

	t.Run("WithAudience", func(t *testing.T) {
		cfg := &config{}
		WithAudience("aud1", "aud2")(cfg)
		assert.Equal(t, []string{"aud1", "aud2"}, cfg.audience)
	})

	t.Run("WithRequestedTokenType", func(t *testing.T) {
		cfg := &config{}
		WithRequestedTokenType(oidc.JWTTokenType)(cfg)
		assert.Equal(t, oidc.JWTTokenType, cfg.requestedTokenType)
	})
}

func TestImpersonate_Validation(t *testing.T) {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")

	t.Run("empty subject token", func(t *testing.T) {
		result, err := Impersonate(ctx, z, "", "actor-token", SubjectIsUserID())
		assert.Nil(t, result)
		assert.EqualError(t, err, "tokenexchange: subject token is required")
	})

	t.Run("empty actor token", func(t *testing.T) {
		result, err := Impersonate(ctx, z, "subject-token", "", SubjectIsUserID())
		assert.Nil(t, result)
		assert.EqualError(t, err, "tokenexchange: actor token is required for impersonation")
	})
}

func TestExchange_Validation(t *testing.T) {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")

	t.Run("empty subject token", func(t *testing.T) {
		result, err := Exchange(ctx, z, "", SubjectIsAccessToken())
		assert.Nil(t, result)
		assert.EqualError(t, err, "tokenexchange: subject token is required")
	})
}

func TestDelegate_IsAliasForImpersonate(t *testing.T) {
	// Delegate should behave identically to Impersonate
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")

	// Both should fail with the same validation error
	_, errImpersonate := Impersonate(ctx, z, "", "actor", SubjectIsUserID())
	_, errDelegate := Delegate(ctx, z, "", "actor", SubjectIsUserID())

	assert.Equal(t, errImpersonate, errDelegate)
}

func TestImpersonate_Integration(t *testing.T) {
	// Mock OIDC discovery and token exchange endpoints
	var receivedRequest struct {
		GrantType          string
		SubjectToken       string
		SubjectTokenType   string
		ActorToken         string
		ActorTokenType     string
		Scope              string
		Audience           string
		RequestedTokenType string
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			discovery := map[string]interface{}{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/oauth/v2/token",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(discovery)

		case "/oauth/v2/token":
			require.NoError(t, r.ParseForm())
			receivedRequest.GrantType = r.FormValue("grant_type")
			receivedRequest.SubjectToken = r.FormValue("subject_token")
			receivedRequest.SubjectTokenType = r.FormValue("subject_token_type")
			receivedRequest.ActorToken = r.FormValue("actor_token")
			receivedRequest.ActorTokenType = r.FormValue("actor_token_type")
			receivedRequest.Scope = r.FormValue("scope")
			receivedRequest.Audience = r.FormValue("audience")
			receivedRequest.RequestedTokenType = r.FormValue("requested_token_type")

			response := map[string]interface{}{
				"access_token":      "new-access-token",
				"token_type":        "Bearer",
				"expires_in":        3600,
				"scope":             "openid profile",
				"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Extract host from server URL (remove http://)
	host := server.URL[7:]

	ctx := context.Background()
	z := zitadel.New(host, zitadel.WithInsecure(""))

	t.Run("impersonate by user ID", func(t *testing.T) {
		result, err := Impersonate(ctx, z,
			"user-123",
			"actor-token",
			SubjectIsUserID(),
			WithScopes("openid", "profile"),
		)

		require.NoError(t, err)
		assert.Equal(t, "new-access-token", result.AccessToken)
		assert.Equal(t, "Bearer", result.TokenType)
		assert.Equal(t, 3600, result.ExpiresIn)

		assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", receivedRequest.GrantType)
		assert.Equal(t, "user-123", receivedRequest.SubjectToken)
		assert.Equal(t, string(UserIDTokenType), receivedRequest.SubjectTokenType)
		assert.Equal(t, "actor-token", receivedRequest.ActorToken)
		assert.Equal(t, string(oidc.AccessTokenType), receivedRequest.ActorTokenType)
	})

	t.Run("impersonate with access token", func(t *testing.T) {
		result, err := Impersonate(ctx, z,
			"user-access-token",
			"actor-token",
			SubjectIsAccessToken(),
		)

		require.NoError(t, err)
		assert.Equal(t, "new-access-token", result.AccessToken)
		assert.Equal(t, string(oidc.AccessTokenType), receivedRequest.SubjectTokenType)
	})

	t.Run("impersonate with ID token", func(t *testing.T) {
		result, err := Impersonate(ctx, z,
			"user-id-token",
			"actor-token",
			SubjectIsIDToken(),
		)

		require.NoError(t, err)
		assert.Equal(t, "new-access-token", result.AccessToken)
		assert.Equal(t, string(oidc.IDTokenType), receivedRequest.SubjectTokenType)
	})

	t.Run("impersonate with actor ID token", func(t *testing.T) {
		result, err := Impersonate(ctx, z,
			"user-123",
			"actor-id-token",
			SubjectIsUserID(),
			ActorIsIDToken(),
		)

		require.NoError(t, err)
		assert.Equal(t, "new-access-token", result.AccessToken)
		assert.Equal(t, string(oidc.IDTokenType), receivedRequest.ActorTokenType)
	})

	t.Run("impersonate requesting JWT", func(t *testing.T) {
		_, err := Impersonate(ctx, z,
			"user-123",
			"actor-token",
			SubjectIsUserID(),
			WithRequestedTokenType(oidc.JWTTokenType),
		)

		require.NoError(t, err)
		assert.Equal(t, string(oidc.JWTTokenType), receivedRequest.RequestedTokenType)
	})
}

func TestExchange_Integration(t *testing.T) {
	var receivedRequest struct {
		GrantType        string
		SubjectToken     string
		SubjectTokenType string
		ActorToken       string
		Scope            string
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			discovery := map[string]interface{}{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/oauth/v2/token",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(discovery)

		case "/oauth/v2/token":
			require.NoError(t, r.ParseForm())
			receivedRequest.GrantType = r.FormValue("grant_type")
			receivedRequest.SubjectToken = r.FormValue("subject_token")
			receivedRequest.SubjectTokenType = r.FormValue("subject_token_type")
			receivedRequest.ActorToken = r.FormValue("actor_token")
			receivedRequest.Scope = r.FormValue("scope")

			response := map[string]interface{}{
				"access_token":      "exchanged-token",
				"token_type":        "Bearer",
				"expires_in":        3600,
				"scope":             "openid",
				"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	host := server.URL[7:]

	ctx := context.Background()
	z := zitadel.New(host, zitadel.WithInsecure(""))

	t.Run("simple exchange", func(t *testing.T) {
		result, err := Exchange(ctx, z,
			"my-access-token",
			SubjectIsAccessToken(),
			WithScopes("openid"),
		)

		require.NoError(t, err)
		assert.Equal(t, "exchanged-token", result.AccessToken)
		assert.Equal(t, "Bearer", result.TokenType)

		assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", receivedRequest.GrantType)
		assert.Equal(t, "my-access-token", receivedRequest.SubjectToken)
		assert.Equal(t, string(oidc.AccessTokenType), receivedRequest.SubjectTokenType)
		assert.Empty(t, receivedRequest.ActorToken)
	})
}

//goland:noinspection HttpUrlsUsage
func TestCustomHeaders_Integration(t *testing.T) {
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()

		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			discovery := map[string]interface{}{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/oauth/v2/token",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(discovery)

		case "/oauth/v2/token":
			response := map[string]interface{}{
				"access_token":      "token",
				"token_type":        "Bearer",
				"expires_in":        3600,
				"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	host := server.URL[7:]

	ctx := context.Background()
	z := zitadel.New(host,
		zitadel.WithInsecure(""),
		zitadel.WithTransportHeader("X-Custom-Header", "custom-value"),
		zitadel.WithTransportHeader("X-Another-Header", "another-value"),
	)

	_, err := Exchange(ctx, z, "token", SubjectIsAccessToken())
	require.NoError(t, err)

	assert.Equal(t, "custom-value", receivedHeaders.Get("X-Custom-Header"))
	assert.Equal(t, "another-value", receivedHeaders.Get("X-Another-Header"))
}
