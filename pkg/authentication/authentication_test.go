package authentication_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/crypto"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/authentication"
	"github.com/zitadel/zitadel-go/v3/pkg/authentication/internal"
	zitadeloidc "github.com/zitadel/zitadel-go/v3/pkg/authentication/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

type testContext = *zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]

func generateEncryptionKey() string {
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	return hex.EncodeToString(key)
}

func newAuthContext(subject string) testContext {
	return &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
		UserInfo: &oidc.UserInfo{Subject: subject},
		Tokens:   &oidc.Tokens[*oidc.IDTokenClaims]{IDToken: "id-token"},
	}
}

type stubHandler struct {
	callbackCtx testContext
	logoutURI   string
	encKey      string
}

func (h *stubHandler) Authenticate(_ http.ResponseWriter, _ *http.Request, _ string) {}

func (h *stubHandler) Callback(_ http.ResponseWriter, _ *http.Request) (testContext, string) {
	state, _ := (&authentication.State{RequestedURI: "/dashboard"}).Encrypt(h.encKey)
	if h.callbackCtx != nil {
		return h.callbackCtx, state
	}
	return newAuthContext("user-123"), state
}

func (h *stubHandler) Logout(_ http.ResponseWriter, _ *http.Request, _ testContext, _, redirectURI string) {
	h.logoutURI = redirectURI
}

type emptyStateHandler struct {
	callbackCtx testContext
	encKey      string
}

func (h *emptyStateHandler) Authenticate(_ http.ResponseWriter, _ *http.Request, _ string) {}

func (h *emptyStateHandler) Callback(_ http.ResponseWriter, _ *http.Request) (testContext, string) {
	state, _ := (&authentication.State{RequestedURI: ""}).Encrypt(h.encKey)
	return h.callbackCtx, state
}

func (h *emptyStateHandler) Logout(_ http.ResponseWriter, _ *http.Request, _ testContext, _, _ string) {}

func TestSessionHandling(t *testing.T) {
	encKey := generateEncryptionKey()
	authCtx := newAuthContext("test-user")

	handler := &stubHandler{callbackCtx: authCtx, encKey: encKey}
	initHandler := func(_ context.Context, _ *zitadel.Zitadel) (authentication.Handler[testContext], error) {
		return handler, nil
	}

	t.Run("custom session store", func(t *testing.T) {
		sessions := internal.NewMockSessionStore[testContext]()
		auth, err := authentication.New(context.Background(), nil, encKey, initHandler,
			authentication.WithSessionStore[testContext](sessions),
		)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
		auth.ServeHTTP(rec, req)

		assert.True(t, sessions.SetCalled)
	})

	t.Run("stateful session lookup", func(t *testing.T) {
		sessions := internal.NewMockSessionStore[testContext]()
		auth, err := authentication.New(context.Background(), nil, encKey, initHandler,
			authentication.WithSessionStore[testContext](sessions),
		)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
		auth.ServeHTTP(rec, req)
		require.Equal(t, http.StatusFound, rec.Code)

		cookie := rec.Result().Cookies()[0]
		auth2, _ := authentication.New(context.Background(), nil, encKey, initHandler,
			authentication.WithSessionStore[testContext](sessions),
		)
		req2 := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req2.AddCookie(cookie)
		_, err = auth2.IsAuthenticated(req2)

		require.NoError(t, err)
		assert.True(t, sessions.GetCalled)
	})

	t.Run("stateless cookie session", func(t *testing.T) {
		sessions := internal.NewMockSessionStore[testContext]()
		auth, err := authentication.New(context.Background(), nil, encKey, initHandler,
			authentication.WithCookieSession[testContext](true),
		)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
		auth.ServeHTTP(rec, req)
		require.Equal(t, http.StatusFound, rec.Code)

		cookie := rec.Result().Cookies()[0]
		auth2, _ := authentication.New(context.Background(), nil, encKey, initHandler,
			authentication.WithCookieSession[testContext](true),
		)
		req2 := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req2.AddCookie(cookie)
		ctx, err := auth2.IsAuthenticated(req2)

		require.NoError(t, err)
		assert.Equal(t, authCtx.GetUserInfo().GetSubject(), ctx.GetUserInfo().GetSubject())
		assert.False(t, sessions.GetCalled)
	})
}

func TestLogout(t *testing.T) {
	tests := []struct {
		name        string
		customURI   string
		requestURL  string
		expectedURI string
	}{
		{
			name:        "custom redirect URI",
			customURI:   "https://app.example.com/signed-out",
			requestURL:  "/auth/logout",
			expectedURI: "https://app.example.com/signed-out",
		},
		{
			name:        "default redirect URI",
			requestURL:  "https://example.com/auth/logout",
			expectedURI: "https://example.com/",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encKey := generateEncryptionKey()
			handler := &stubHandler{encKey: encKey}
			initHandler := func(_ context.Context, _ *zitadel.Zitadel) (authentication.Handler[testContext], error) {
				return handler, nil
			}

			sessions := authentication.NewInMemorySessions[testContext]()
			sessionID := uuid.NewString()
			_ = sessions.Set(sessionID, newAuthContext("user"))

			opts := []authentication.Option[testContext]{
				authentication.WithSessionStore(sessions),
				authentication.WithSessionCookieName[testContext]("sid"),
			}
			if tc.customURI != "" {
				opts = append(opts, authentication.WithPostLogoutRedirectURI[testContext](tc.customURI))
			}

			auth, err := authentication.New(context.Background(), nil, encKey, initHandler, opts...)
			require.NoError(t, err)

			cookieVal, _ := crypto.EncryptAES(sessionID, encKey)
			req := httptest.NewRequest(http.MethodGet, tc.requestURL, nil)
			req.AddCookie(&http.Cookie{Name: "sid", Value: cookieVal})

			auth.ServeHTTP(httptest.NewRecorder(), req)

			assert.Equal(t, tc.expectedURI, handler.logoutURI)
		})
	}
}

func TestCallbackRedirectsToRootOnEmptyURI(t *testing.T) {
	encKey := generateEncryptionKey()
	handler := &emptyStateHandler{
		callbackCtx: newAuthContext("user"),
		encKey:      encKey,
	}
	initHandler := func(_ context.Context, _ *zitadel.Zitadel) (authentication.Handler[testContext], error) {
		return handler, nil
	}

	auth, err := authentication.New(context.Background(), nil, encKey, initHandler,
		authentication.WithCookieSession[testContext](true),
	)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	auth.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "/", rec.Header().Get("Location"))
}

func TestStateEncryptionError(t *testing.T) {
	s := &authentication.State{RequestedURI: "/test"}
	_, err := s.Encrypt("bad-key")
	assert.Error(t, err)
}
