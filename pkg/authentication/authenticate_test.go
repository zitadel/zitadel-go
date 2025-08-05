package authentication_test

import (
	"context"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/zitadel/oidc/v3/pkg/crypto"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zitadel/zitadel-go/v3/pkg/authentication"
	zitadeloidc "github.com/zitadel/zitadel-go/v3/pkg/authentication/oidc"
)

type mockHandler[T authentication.Ctx] struct {
	CapturedLogoutURI string
}

func (m *mockHandler[T]) Authenticate(_ http.ResponseWriter, _ *http.Request, _ string) {}

func (m *mockHandler[T]) Callback(_ http.ResponseWriter, _ *http.Request) (T, string) {
	var t T
	if newCtx, ok := any(t).(*zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]); ok {
		newCtx = &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
			Tokens: &oidc.Tokens[*oidc.IDTokenClaims]{IDToken: "dummy-id-token"},
		}
		return any(newCtx).(T), "dummy-state"
	}
	return t, "dummy-state"
}

func (m *mockHandler[T]) Logout(_ http.ResponseWriter, _ *http.Request, _ T, _, optionalRedirectURI string) {
	m.CapturedLogoutURI = optionalRedirectURI
}

// TestAuthenticator_Logout_WithCustomURI verifies that when the Authenticator is
// initialized with the WithPostLogoutRedirectURI option, it correctly passes the
// specified custom URI down to the underlying handler during the logout process.
//
// TestAuthenticator_Logout_WithDefaultURI verifies the fallback behavior of the
// Authenticator's Logout method. When no custom post-logout URI is provided,
// it should construct a default URI based on the incoming request's host and
// pass that to the underlying handler.
func TestAuthenticator_Logout(t *testing.T) {
	type CtxType = *zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]

	tests := []struct {
		name             string
		customLogoutURL  string
		requestURL       string
		useCustomURI     bool
		expectedURI      string
		assertionMessage string
	}{
		{
			name:             "WithCustomURI",
			customLogoutURL:  "https://myapp.com/goodbye",
			requestURL:       "/auth/logout",
			useCustomURI:     true,
			expectedURI:      "https://myapp.com/goodbye",
			assertionMessage: "The post-logout-uri should match the default",
		},
		{
			name:             "WithDefaultURI",
			requestURL:       "https://example.com/auth/logout",
			useCustomURI:     false,
			expectedURI:      "https://example.com/",
			assertionMessage: "The post-logout-uri should match the default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockHandler[CtxType]{}
			mockInitializer := func(ctx context.Context, z *zitadel.Zitadel) (authentication.Handler[CtxType], error) {
				return mock, nil
			}

			key := "01234567890123456789012345678901"

			sessions := authentication.NewInMemorySessions[CtxType]()
			sessionID := uuid.Must(uuid.NewRandom()).String()
			err := sessions.Set(sessionID, &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{})
			if err != nil {
				t.Fatalf("test setup failed: could not set session: %v", err)
			}

			// Build options based on test case
			options := []authentication.Option[CtxType]{
				authentication.WithSessionStore(sessions),
				authentication.WithSessionCookieName[CtxType]("sid"),
			}

			if tt.useCustomURI {
				options = append(options, authentication.WithPostLogoutRedirectURI[CtxType](tt.customLogoutURL))
			}

			authenticator, _ := authentication.New(
				context.Background(), nil, key, mockInitializer,
				options...,
			)

			req := httptest.NewRequest("GET", tt.requestURL, nil)
			cookieValue, _ := crypto.EncryptAES(sessionID, key)
			req.AddCookie(&http.Cookie{Name: "sid", Value: cookieValue})
			recorder := httptest.NewRecorder()

			authenticator.ServeHTTP(recorder, req)

			assert.Equal(t, tt.expectedURI, mock.CapturedLogoutURI, tt.assertionMessage)
		})
	}
}
