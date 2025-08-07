package authentication_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"

	"github.com/zitadel/zitadel-go/v3/pkg/authentication"
	zitadeloidc "github.com/zitadel/zitadel-go/v3/pkg/authentication/oidc"
)

// CtxType is an alias for the specific context type used in these tests.
type CtxType = *zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]

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

// mockHandler is a test double for the Handler interface, configured to
// support the session-related tests.
type mockHandler struct {
	callbackResponse CtxType
}

func (m *mockHandler) Authenticate(_ http.ResponseWriter, _ *http.Request, _ string) {}

func (m *mockHandler) Callback(_ http.ResponseWriter, _ *http.Request) (CtxType, string) {
	state, _ := (&authentication.State{RequestedURI: "/profile"}).Encrypt("01234567890123456789012345678901")
	return m.callbackResponse, state
}

// Logout is implemented to satisfy the interface, but not used in this test suite.
func (m *mockHandler) Logout(_ http.ResponseWriter, _ *http.Request, _ CtxType, _, _ string) {}

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

// TestAuthenticator_WithCookieSession verifies that when WithCookieSession is
// enabled, the full session context is stored encrypted in the cookie.
func TestAuthenticator_WithCookieSession(t *testing.T) {
	key := "01234567890123456789012345678901"
	authCtxToStore := newTestAuthContext("test-sub-cookie")
	mock := &mockHandler{callbackResponse: authCtxToStore}
	mockInitializer := func(ctx context.Context, z *zitadel.Zitadel) (authentication.Handler[CtxType], error) {
		return mock, nil
	}
	authenticator, err := authentication.New(
		context.Background(), nil, key, mockInitializer,
		authentication.WithCookieSession[CtxType](true),
	)
	require.NoError(t, err)

	callbackReq := httptest.NewRequest("GET", "/auth/callback", nil)
	recorder := httptest.NewRecorder()
	authenticator.ServeHTTP(recorder, callbackReq)

	require.Equal(t, http.StatusFound, recorder.Code)
	cookie := recorder.Result().Cookies()[0]
	require.NotNil(t, cookie)

	// To prove statelessness, create a new authenticator which has a new, empty session store.
	newAuthenticator, _ := authentication.New(
		context.Background(), nil, key, mockInitializer,
		authentication.WithCookieSession[CtxType](true),
	)
	authedReq := httptest.NewRequest("GET", "/protected", nil)
	authedReq.AddCookie(cookie)
	retrievedCtx, err := newAuthenticator.IsAuthenticated(authedReq)

	require.NoError(t, err)
	assert.Equal(t, authCtxToStore.GetUserInfo().GetSubject(), retrievedCtx.GetUserInfo().GetSubject())
}

// TestAuthenticator_StatefulSession verifies the default stateful session
// behavior, where a session ID is stored in the cookie and the full context
// is stored in the provided session store.
func TestAuthenticator_StatefulSession(t *testing.T) {
	key := "01234567890123456789012345678901"
	authCtxToStore := newTestAuthContext("test-sub-stateful")
	mock := &mockHandler{callbackResponse: authCtxToStore}
	mockInitializer := func(ctx context.Context, z *zitadel.Zitadel) (authentication.Handler[CtxType], error) {
		return mock, nil
	}
	mockSessions := &mockSessionStore{}
	authenticator, err := authentication.New(
		context.Background(), nil, key, mockInitializer,
		authentication.WithSessionStore[CtxType](mockSessions),
	)
	require.NoError(t, err)

	callbackReq := httptest.NewRequest("GET", "/auth/callback", nil)
	recorder := httptest.NewRecorder()
	authenticator.ServeHTTP(recorder, callbackReq)

	require.Equal(t, http.StatusFound, recorder.Code)
	cookie := recorder.Result().Cookies()[0]
	require.NotNil(t, cookie)

	authedReq := httptest.NewRequest("GET", "/protected", nil)
	authedReq.AddCookie(cookie)
	_, err = authenticator.IsAuthenticated(authedReq)

	require.NoError(t, err)
	assert.True(t, mockSessions.GetWasCalled, "the custom session store's Get method should have been called")
}

// TestAuthenticator_WithSessionStore verifies that the Authenticator correctly
// uses a custom session store when one is provided via the WithSessionStore option.
func TestAuthenticator_WithSessionStore(t *testing.T) {
	key := "01234567890123456789012345678901"
	mockSessions := &mockSessionStore{}
	mock := &mockHandler{
		callbackResponse: newTestAuthContext("test-sub"),
	}
	mockInitializer := func(ctx context.Context, z *zitadel.Zitadel) (authentication.Handler[CtxType], error) {
		return mock, nil
	}

	authenticator, err := authentication.New(
		context.Background(), nil, key, mockInitializer,
		authentication.WithSessionStore[CtxType](mockSessions),
	)
	require.NoError(t, err)

	callbackReq := httptest.NewRequest("GET", "/auth/callback", nil)
	recorder := httptest.NewRecorder()
	authenticator.ServeHTTP(recorder, callbackReq)

	require.Equal(t, http.StatusFound, recorder.Code)
	assert.True(t, mockSessions.SetWasCalled)
}
