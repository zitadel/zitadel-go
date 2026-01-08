package authentication_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/crypto"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/authentication"
	zitadeloidc "github.com/zitadel/zitadel-go/v3/pkg/authentication/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

// CtxType is an alias for the specific context type used in these tests.
type CtxType = *zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]

const testEncryptionKey = "01234567890123456789012345678901"

// newTestAuthContext is a helper that creates a valid, non-nil auth context.
func newTestAuthContext(subject string) CtxType {
	return &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
		UserInfo: &oidc.UserInfo{
			Subject: subject,
		},
		Tokens: &oidc.Tokens[*oidc.IDTokenClaims]{
			IDToken: "test-id-token",
		},
	}
}

// mockHandler is a flexible test double for the Handler interface.
type mockHandler struct {
	CallbackResponse  CtxType
	CapturedLogoutURI string
}

func (m *mockHandler) Authenticate(_ http.ResponseWriter, _ *http.Request, _ string) {}

func (m *mockHandler) Callback(_ http.ResponseWriter, _ *http.Request) (CtxType, string) {
	state, _ := (&authentication.State{RequestedURI: "/profile"}).Encrypt(testEncryptionKey)
	if m.CallbackResponse != nil {
		return m.CallbackResponse, state
	}
	return newTestAuthContext("dummy-subject"), "dummy-state"
}

func (m *mockHandler) Logout(_ http.ResponseWriter, _ *http.Request, _ CtxType, _, optionalRedirectURI string) {
	m.CapturedLogoutURI = optionalRedirectURI
}

// mockSessionStore is a test double for the Sessions interface.
type mockSessionStore struct {
	SetWasCalled bool
	GetWasCalled bool
	store        map[string]CtxType
}

func (m *mockSessionStore) Set(id string, session CtxType) error {
	m.SetWasCalled = true
	if m.store == nil {
		m.store = make(map[string]CtxType)
	}
	m.store[id] = session
	return nil
}

func (m *mockSessionStore) Get(id string) (CtxType, error) {
	m.GetWasCalled = true
	s, ok := m.store[id]
	if !ok {
		return nil, errors.New("no session")
	}
	return s, nil
}

func TestAuthenticator_SessionHandling(t *testing.T) {
	authCtxToStore := newTestAuthContext("test-subject")
	mock := &mockHandler{CallbackResponse: authCtxToStore}
	mockInitializer := func(ctx context.Context, z *zitadel.Zitadel) (authentication.Handler[CtxType], error) {
		return mock, nil
	}

	tests := []struct {
		name    string
		options func(sessions *mockSessionStore) []authentication.Option[CtxType]
		assert  func(t *testing.T, cookie *http.Cookie, sessions *mockSessionStore)
	}{
		{
			name: "uses a custom session store when provided",
			options: func(sessions *mockSessionStore) []authentication.Option[CtxType] {
				return []authentication.Option[CtxType]{authentication.WithSessionStore[CtxType](sessions)}
			},
			assert: func(t *testing.T, cookie *http.Cookie, sessions *mockSessionStore) {
				assert.True(t, sessions.SetWasCalled, "The custom session store's Set method should have been called")
			},
		},
		{
			name: "uses stateful session by default",
			options: func(sessions *mockSessionStore) []authentication.Option[CtxType] {
				return []authentication.Option[CtxType]{authentication.WithSessionStore[CtxType](sessions)}
			},
			assert: func(t *testing.T, cookie *http.Cookie, sessions *mockSessionStore) {
				authenticator, _ := authentication.New(
					context.Background(), nil, testEncryptionKey, mockInitializer,
					authentication.WithSessionStore[CtxType](sessions),
				)
				authedReq := httptest.NewRequest("GET", "/protected", nil)
				authedReq.AddCookie(cookie)
				_, err := authenticator.IsAuthenticated(authedReq)
				require.NoError(t, err)
				assert.True(t, sessions.GetWasCalled, "The session store's Get method should have been called")
			},
		},
		{
			name: "uses stateless cookie session when enabled",
			options: func(sessions *mockSessionStore) []authentication.Option[CtxType] {
				return []authentication.Option[CtxType]{authentication.WithCookieSession[CtxType](true)}
			},
			assert: func(t *testing.T, cookie *http.Cookie, sessions *mockSessionStore) {
				// To prove statelessness, create a new authenticator with a new, empty session store.
				newAuthenticator, _ := authentication.New(
					context.Background(), nil, testEncryptionKey, mockInitializer,
					authentication.WithCookieSession[CtxType](true),
				)
				authedReq := httptest.NewRequest("GET", "/protected", nil)
				authedReq.AddCookie(cookie)
				retrievedCtx, err := newAuthenticator.IsAuthenticated(authedReq)
				require.NoError(t, err)
				assert.Equal(t, authCtxToStore.GetUserInfo().GetSubject(), retrievedCtx.GetUserInfo().GetSubject())
				assert.False(t, sessions.GetWasCalled, "The session store's Get method should not have been called")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSessions := &mockSessionStore{}
			authenticator, err := authentication.New(
				context.Background(), nil, testEncryptionKey, mockInitializer,
				tt.options(mockSessions)...,
			)
			require.NoError(t, err)
			callbackReq := httptest.NewRequest("GET", "/auth/callback", nil)
			recorder := httptest.NewRecorder()
			authenticator.ServeHTTP(recorder, callbackReq)
			require.Equal(t, http.StatusFound, recorder.Code)
			cookie := recorder.Result().Cookies()[0]
			require.NotNil(t, cookie)

			tt.assert(t, cookie, mockSessions)
		})
	}
}

func TestAuthenticator_Logout(t *testing.T) {
	tests := []struct {
		name            string
		customLogoutURL string
		requestURL      string
		useCustomURI    bool
		expectedURI     string
	}{
		{
			name:            "WithCustomURI",
			customLogoutURL: "https://myapp.com/goodbye",
			requestURL:      "/auth/logout",
			useCustomURI:    true,
			expectedURI:     "https://myapp.com/goodbye",
		},
		{
			name:         "WithDefaultURI",
			requestURL:   "https://example.com/auth/logout",
			useCustomURI: false,
			expectedURI:  "https://example.com/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockHandler{}
			mockInitializer := func(ctx context.Context, z *zitadel.Zitadel) (authentication.Handler[CtxType], error) {
				return mock, nil
			}

			// For logout, a valid session must exist first.
			sessions := authentication.NewInMemorySessions[CtxType]()
			sessionID := uuid.Must(uuid.NewRandom()).String()
			require.NoError(t, sessions.Set(sessionID, newTestAuthContext("logout-user")))

			options := []authentication.Option[CtxType]{
				authentication.WithSessionStore(sessions),
				authentication.WithSessionCookieName[CtxType]("sid"),
			}

			if tt.useCustomURI {
				options = append(options, authentication.WithPostLogoutRedirectURI[CtxType](tt.customLogoutURL))
			}

			authenticator, err := authentication.New(context.Background(), nil, testEncryptionKey, mockInitializer, options...)
			require.NoError(t, err)

			req := httptest.NewRequest("GET", tt.requestURL, nil)
			cookieValue, _ := crypto.EncryptAES(sessionID, testEncryptionKey)
			req.AddCookie(&http.Cookie{Name: "sid", Value: cookieValue})
			recorder := httptest.NewRecorder()

			authenticator.ServeHTTP(recorder, req)

			assert.Equal(t, tt.expectedURI, mock.CapturedLogoutURI, fmt.Sprintf("Test: %s", tt.name))
		})
	}
}
