package tokenexchange

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
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

	t.Run("WithResource", func(t *testing.T) {
		cfg := &config{}
		WithResource("https://api.example.com")(cfg)
		assert.Equal(t, []string{"https://api.example.com"}, cfg.resource)
	})

	t.Run("WithRequestedTokenType", func(t *testing.T) {
		cfg := &config{}
		WithRequestedTokenType(oidc.JWTTokenType)(cfg)
		assert.Equal(t, oidc.JWTTokenType, cfg.requestedTokenType)
	})

	t.Run("WithClientAuth", func(t *testing.T) {
		cfg := &config{}
		auth := ClientCredentials("client-id", "client-secret")
		WithClientAuth(auth)(cfg)
		assert.NotNil(t, cfg.clientAuth)
	})
}

func TestClientCredentials(t *testing.T) {
	auth := ClientCredentials("my-client", "my-secret")
	assert.NotNil(t, auth)

	cca, ok := auth.(*clientCredentialsAuth)
	require.True(t, ok)
	assert.Equal(t, "my-client", cca.clientID)
	assert.Equal(t, "my-secret", cca.clientSecret)
}

func TestJWTProfile(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)

	auth := JWTProfile("my-client", signer)
	assert.NotNil(t, auth)

	jpa, ok := auth.(*jwtProfileAuth)
	require.True(t, ok)
	assert.Equal(t, "my-client", jpa.clientID)
	assert.NotNil(t, jpa.signer)
}

func TestImpersonate_Validation(t *testing.T) {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")
	auth := ClientCredentials("client", "secret")

	t.Run("empty subject token", func(t *testing.T) {
		result, err := Impersonate(ctx, z, "", "actor-token", SubjectIsUserID(), WithClientAuth(auth))
		assert.Nil(t, result)
		assert.EqualError(t, err, "tokenexchange: subject token is required")
	})

	t.Run("empty actor token", func(t *testing.T) {
		result, err := Impersonate(ctx, z, "subject-token", "", SubjectIsUserID(), WithClientAuth(auth))
		assert.Nil(t, result)
		assert.EqualError(t, err, "tokenexchange: actor token is required for impersonation")
	})

	t.Run("missing client auth", func(t *testing.T) {
		result, err := Impersonate(ctx, z, "subject-token", "actor-token", SubjectIsUserID())
		assert.Nil(t, result)
		assert.EqualError(t, err, "tokenexchange: client authentication is required; use WithClientAuth")
	})
}

func TestExchange_Validation(t *testing.T) {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")
	auth := ClientCredentials("client", "secret")

	t.Run("empty subject token", func(t *testing.T) {
		result, err := Exchange(ctx, z, "", SubjectIsAccessToken(), WithClientAuth(auth))
		assert.Nil(t, result)
		assert.EqualError(t, err, "tokenexchange: subject token is required")
	})

	t.Run("missing client auth", func(t *testing.T) {
		result, err := Exchange(ctx, z, "subject-token", SubjectIsAccessToken())
		assert.Nil(t, result)
		assert.EqualError(t, err, "tokenexchange: client authentication is required; use WithClientAuth")
	})
}

func TestDelegate_IsAliasForImpersonate(t *testing.T) {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")

	_, errImpersonate := Impersonate(ctx, z, "", "actor", SubjectIsUserID())
	_, errDelegate := Delegate(ctx, z, "", "actor", SubjectIsUserID())

	assert.Equal(t, errImpersonate, errDelegate)
}

func TestImpersonate_Integration(t *testing.T) {
	var receivedRequest struct {
		GrantType          string
		SubjectToken       string
		SubjectTokenType   string
		ActorToken         string
		ActorTokenType     string
		Scope              string
		Audience           string
		Resource           string
		RequestedTokenType string
	}
	var receivedAuth struct {
		Username string
		Password string
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
			receivedAuth.Username, receivedAuth.Password, _ = r.BasicAuth()

			require.NoError(t, r.ParseForm())
			receivedRequest.GrantType = r.FormValue("grant_type")
			receivedRequest.SubjectToken = r.FormValue("subject_token")
			receivedRequest.SubjectTokenType = r.FormValue("subject_token_type")
			receivedRequest.ActorToken = r.FormValue("actor_token")
			receivedRequest.ActorTokenType = r.FormValue("actor_token_type")
			receivedRequest.Scope = r.FormValue("scope")
			receivedRequest.Audience = r.FormValue("audience")
			receivedRequest.Resource = r.FormValue("resource")
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

	host := server.URL[7:]
	ctx := context.Background()
	z := zitadel.New(host, zitadel.WithInsecure(""))
	auth := ClientCredentials("test-client", "test-secret")

	t.Run("impersonate by user ID with client credentials", func(t *testing.T) {
		result, err := Impersonate(ctx, z,
			"user-123",
			"actor-token",
			SubjectIsUserID(),
			WithScopes("openid", "profile"),
			WithClientAuth(auth),
		)

		require.NoError(t, err)
		assert.Equal(t, "new-access-token", result.AccessToken)
		assert.Equal(t, "Bearer", result.TokenType)
		assert.Equal(t, 3600, result.ExpiresIn)

		assert.Equal(t, "test-client", receivedAuth.Username)
		assert.Equal(t, "test-secret", receivedAuth.Password)
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
			WithClientAuth(auth),
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
			WithClientAuth(auth),
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
			WithClientAuth(auth),
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
			WithClientAuth(auth),
		)

		require.NoError(t, err)
		assert.Equal(t, string(oidc.JWTTokenType), receivedRequest.RequestedTokenType)
	})

	t.Run("impersonate with resource", func(t *testing.T) {
		_, err := Impersonate(ctx, z,
			"user-123",
			"actor-token",
			SubjectIsUserID(),
			WithResource("https://api.example.com"),
			WithClientAuth(auth),
		)

		require.NoError(t, err)
		assert.Equal(t, "https://api.example.com", receivedRequest.Resource)
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
	var receivedAuth struct {
		Username string
		Password string
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
			receivedAuth.Username, receivedAuth.Password, _ = r.BasicAuth()

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
	auth := ClientCredentials("test-client", "test-secret")

	t.Run("simple exchange with client credentials", func(t *testing.T) {
		result, err := Exchange(ctx, z,
			"my-access-token",
			SubjectIsAccessToken(),
			WithScopes("openid"),
			WithClientAuth(auth),
		)

		require.NoError(t, err)
		assert.Equal(t, "exchanged-token", result.AccessToken)
		assert.Equal(t, "Bearer", result.TokenType)

		assert.Equal(t, "test-client", receivedAuth.Username)
		assert.Equal(t, "test-secret", receivedAuth.Password)
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", receivedRequest.GrantType)
		assert.Equal(t, "my-access-token", receivedRequest.SubjectToken)
		assert.Equal(t, string(oidc.AccessTokenType), receivedRequest.SubjectTokenType)
		assert.Empty(t, receivedRequest.ActorToken)
	})
}

//goland:noinspection HttpUrlsUsage
func TestJWTProfile_Integration(t *testing.T) {
	var receivedRequest struct {
		GrantType            string
		SubjectToken         string
		SubjectTokenType     string
		ClientAssertionType  string
		ClientAssertion      string
		ClientID             string
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
			receivedRequest.ClientAssertionType = r.FormValue("client_assertion_type")
			receivedRequest.ClientAssertion = r.FormValue("client_assertion")
			receivedRequest.ClientID = r.FormValue("client_id")

			response := map[string]interface{}{
				"access_token":      "jwt-profile-token",
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
	z := zitadel.New(host, zitadel.WithInsecure(""))

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)

	auth := JWTProfile("jwt-client-id", signer)

	t.Run("exchange with JWT profile authentication", func(t *testing.T) {
		result, err := Exchange(ctx, z,
			"my-access-token",
			SubjectIsAccessToken(),
			WithClientAuth(auth),
		)

		require.NoError(t, err)
		assert.Equal(t, "jwt-profile-token", result.AccessToken)
		assert.Equal(t, "Bearer", result.TokenType)

		assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", receivedRequest.GrantType)
		assert.Equal(t, "my-access-token", receivedRequest.SubjectToken)
		assert.Equal(t, string(oidc.AccessTokenType), receivedRequest.SubjectTokenType)
		assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", receivedRequest.ClientAssertionType)
		assert.NotEmpty(t, receivedRequest.ClientAssertion)
		assert.True(t, strings.HasPrefix(receivedRequest.ClientAssertion, "eyJ"), "client assertion should be a JWT")
	})

	t.Run("impersonate with JWT profile authentication", func(t *testing.T) {
		result, err := Impersonate(ctx, z,
			"user-456",
			"actor-token",
			SubjectIsUserID(),
			WithClientAuth(auth),
		)

		require.NoError(t, err)
		assert.Equal(t, "jwt-profile-token", result.AccessToken)
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", receivedRequest.GrantType)
		assert.Equal(t, "user-456", receivedRequest.SubjectToken)
		assert.Equal(t, string(UserIDTokenType), receivedRequest.SubjectTokenType)
		assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", receivedRequest.ClientAssertionType)
		assert.NotEmpty(t, receivedRequest.ClientAssertion)
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
	auth := ClientCredentials("client", "secret")

	_, err := Exchange(ctx, z, "token", SubjectIsAccessToken(), WithClientAuth(auth))
	require.NoError(t, err)

	assert.Equal(t, "custom-value", receivedHeaders.Get("X-Custom-Header"))
	assert.Equal(t, "another-value", receivedHeaders.Get("X-Another-Header"))
}
