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
func TestAuthenticator_Logout_WithCustomURI(t *testing.T) {
	type CtxType = *zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]
	mock := &mockHandler[CtxType]{}
	mockInitializer := func(ctx context.Context, z *zitadel.Zitadel) (authentication.Handler[CtxType], error) {
		return mock, nil
	}

	key := "01234567890123456789012345678901"
	customLogoutURL := "https://myapp.com/goodbye"

	sessions := authentication.NewInMemorySessions[CtxType]()
	sessionID := uuid.Must(uuid.NewRandom()).String()
	err := sessions.Set(sessionID, &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{})
	if err != nil {
		t.Fatalf("test setup failed: could not set session: %v", err)
	}

	authenticator, _ := authentication.New(
		context.Background(), nil, key, mockInitializer,
		authentication.WithPostLogoutRedirectURI[CtxType](customLogoutURL),
		authentication.WithSessionStore[CtxType](sessions),
		authentication.WithSessionCookieName[CtxType]("sid"),
	)

	req := httptest.NewRequest("GET", "/auth/logout", nil)
	cookieValue, _ := crypto.EncryptAES(sessionID, key)
	req.AddCookie(&http.Cookie{Name: "sid", Value: cookieValue})
	recorder := httptest.NewRecorder()

	authenticator.ServeHTTP(recorder, req)

	assert.Equal(t, "https://myapp.com/goodbye", mock.CapturedLogoutURI, "The post-logout-uri should match the default")
}

// TestAuthenticator_Logout_WithDefaultURI verifies the fallback behavior of the
// Authenticator's Logout method. When no custom post-logout URI is provided,
// it should construct a default URI based on the incoming request's host and
// pass that to the underlying handler.
func TestAuthenticator_Logout_WithDefaultURI(t *testing.T) {
	type CtxType = *zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]
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

	authenticator, _ := authentication.New(
		context.Background(), nil, key, mockInitializer,
		authentication.WithSessionStore[CtxType](sessions),
		authentication.WithSessionCookieName[CtxType]("sid"),
	)

	req := httptest.NewRequest("GET", "https://example.com/auth/logout", nil)
	cookieValue, _ := crypto.EncryptAES(sessionID, key)
	req.AddCookie(&http.Cookie{Name: "sid", Value: cookieValue})
	recorder := httptest.NewRecorder()

	authenticator.ServeHTTP(recorder, req)

	assert.Equal(t, "https://example.com/", mock.CapturedLogoutURI, "The post-logout-uri should match the default")
}
