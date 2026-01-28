package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
	"github.com/zitadel/zitadel-go/v3/pkg/http/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/http/middleware/internal"
)

// TestInterceptor_RequireAuthorization_Success verifies that when authorization
// succeeds, the handler is called and returns 200 OK.
func TestInterceptor_RequireAuthorization_Success(t *testing.T) {
	checker := &internal.MockAuthorizationChecker{
		Ctx: internal.NewMockAuthContext("user-123", "org-456"),
	}
	interceptor := middleware.New(checker)

	var handlerCalled bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	wrappedHandler := interceptor.RequireAuthorization()(handler)

	request := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	request.Header.Set("Authorization", "Bearer valid-token")
	response := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(response, request)

	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "success", response.Body.String())
	assert.True(t, handlerCalled)
}

// TestInterceptor_RequireAuthorization_UnauthorizedError verifies that when
// authorization returns an unauthorized error, the middleware returns 401 and
// does not call the handler.
func TestInterceptor_RequireAuthorization_UnauthorizedError(t *testing.T) {
	checker := &internal.MockAuthorizationChecker{
		Err: authorization.NewErrorUnauthorized(errors.New("invalid token")),
	}
	interceptor := middleware.New(checker)

	var handlerCalled bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	wrappedHandler := interceptor.RequireAuthorization()(handler)

	request := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	request.Header.Set("Authorization", "Bearer invalid-token")
	response := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(response, request)

	assert.Equal(t, http.StatusUnauthorized, response.Code)
	assert.Equal(t, "invalid token\n", response.Body.String())
	assert.False(t, handlerCalled)
}

// TestInterceptor_RequireAuthorization_PermissionDenied verifies that when
// authorization returns a permission denied error, the middleware returns 403
// and does not call the handler.
func TestInterceptor_RequireAuthorization_PermissionDenied(t *testing.T) {
	checker := &internal.MockAuthorizationChecker{
		Err: authorization.NewErrorPermissionDenied(errors.New("insufficient permissions")),
	}
	interceptor := middleware.New(checker)

	var handlerCalled bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	wrappedHandler := interceptor.RequireAuthorization()(handler)

	request := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	request.Header.Set("Authorization", "Bearer valid-token")
	response := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(response, request)

	assert.Equal(t, http.StatusForbidden, response.Code)
	assert.Equal(t, "insufficient permissions\n", response.Body.String())
	assert.False(t, handlerCalled)
}

// TestInterceptor_RequireAuthorization_MissingHeader verifies that when the
// authorization header is missing, the middleware returns 401 and does not
// call the handler.
func TestInterceptor_RequireAuthorization_MissingHeader(t *testing.T) {
	checker := &internal.MockAuthorizationChecker{
		Err: authorization.NewErrorUnauthorized(errors.New("missing token")),
	}
	interceptor := middleware.New(checker)

	var handlerCalled bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	wrappedHandler := interceptor.RequireAuthorization()(handler)

	request := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	response := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(response, request)

	assert.Equal(t, http.StatusUnauthorized, response.Code)
	assert.Equal(t, "missing token\n", response.Body.String())
	assert.False(t, handlerCalled)
}

// TestInterceptor_CheckAuthorization_Success verifies that when authorization
// succeeds, the handler is called with the authorization context added to the
// request context.
func TestInterceptor_CheckAuthorization_Success(t *testing.T) {
	checker := &internal.MockAuthorizationChecker{
		Ctx: internal.NewMockAuthContext("user-123", "org-456"),
	}
	interceptor := middleware.New(checker)

	var (
		handlerCalled bool
		handlerCtx    context.Context
	)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		handlerCtx = r.Context()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("handler executed"))
	})

	wrappedHandler := interceptor.CheckAuthorization()(handler)

	request := httptest.NewRequest(http.MethodGet, "/api/optional-auth", nil)
	request.Header.Set("Authorization", "Bearer valid-token")
	response := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(response, request)

	require.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "handler executed", response.Body.String())

	authCtx := authorization.Context[*internal.MockAuthContext](handlerCtx)
	require.NotNil(t, authCtx)
	assert.Equal(t, "user-123", authCtx.UserID())
}

// TestInterceptor_CheckAuthorization_FailedAuth verifies that when authorization
// fails, the handler is still called but without an authorization context.
func TestInterceptor_CheckAuthorization_FailedAuth(t *testing.T) {
	checker := &internal.MockAuthorizationChecker{
		Err: authorization.NewErrorUnauthorized(errors.New("invalid token")),
	}
	interceptor := middleware.New(checker)

	var (
		handlerCalled bool
		handlerCtx    context.Context
	)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		handlerCtx = r.Context()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("handler executed"))
	})

	wrappedHandler := interceptor.CheckAuthorization()(handler)

	request := httptest.NewRequest(http.MethodGet, "/api/optional-auth", nil)
	request.Header.Set("Authorization", "Bearer invalid-token")
	response := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(response, request)

	require.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "handler executed", response.Body.String())

	authCtx := authorization.Context[*internal.MockAuthContext](handlerCtx)
	assert.Nil(t, authCtx)
}

// TestInterceptor_CheckAuthorization_PermissionDenied verifies that when
// authorization returns a permission denied error, the handler is still called
// but without an authorization context.
func TestInterceptor_CheckAuthorization_PermissionDenied(t *testing.T) {
	checker := &internal.MockAuthorizationChecker{
		Err: authorization.NewErrorPermissionDenied(errors.New("insufficient permissions")),
	}
	interceptor := middleware.New(checker)

	//goland:noinspection DuplicatedCode
	var (
		handlerCalled bool
		handlerCtx    context.Context
	)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		handlerCtx = r.Context()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("handler executed"))
	})

	wrappedHandler := interceptor.CheckAuthorization()(handler)

	request := httptest.NewRequest(http.MethodGet, "/api/optional-auth", nil)
	request.Header.Set("Authorization", "Bearer valid-token")
	response := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(response, request)

	require.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "handler executed", response.Body.String())

	authCtx := authorization.Context[*internal.MockAuthContext](handlerCtx)
	assert.Nil(t, authCtx)
}

// TestInterceptor_CheckAuthorization_MissingHeader verifies that when the
// authorization header is missing, the handler is still called but without
// an authorization context.
func TestInterceptor_CheckAuthorization_MissingHeader(t *testing.T) {
	checker := &internal.MockAuthorizationChecker{
		Err: authorization.NewErrorUnauthorized(errors.New("missing token")),
	}
	interceptor := middleware.New(checker)

	var (
		handlerCalled bool
		handlerCtx    context.Context
	)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		handlerCtx = r.Context()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("handler executed"))
	})

	wrappedHandler := interceptor.CheckAuthorization()(handler)

	request := httptest.NewRequest(http.MethodGet, "/api/optional-auth", nil)
	response := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(response, request)

	require.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "handler executed", response.Body.String())

	authCtx := authorization.Context[*internal.MockAuthContext](handlerCtx)
	assert.Nil(t, authCtx)
}

// TestInterceptor_CheckAuthorization_WithOptions verifies that CheckAuthorization
// accepts and correctly passes through authorization options such as role requirements.
func TestInterceptor_CheckAuthorization_WithOptions(t *testing.T) {
	checker := &internal.MockAuthorizationChecker{
		Ctx: internal.NewMockAuthContextWithRoles("admin-user", map[string]bool{
			"admin": true,
		}),
	}
	interceptor := middleware.New(checker)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authCtx := authorization.Context[*internal.MockAuthContext](r.Context())
		if authCtx != nil && authCtx.IsGrantedRole("admin") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("admin access granted"))
		} else {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("not admin"))
		}
	})

	wrappedHandler := interceptor.CheckAuthorization(authorization.WithRole("admin"))(handler)

	request := httptest.NewRequest(http.MethodGet, "/api/admin", nil)
	request.Header.Set("Authorization", "Bearer admin-token")
	response := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(response, request)

	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "admin access granted", response.Body.String())
}

// TestInterceptor_Context verifies that the Context method correctly retrieves
// the authorization context from a request context.
func TestInterceptor_Context(t *testing.T) {
	expectedAuthCtx := internal.NewMockAuthContext("user-123", "org-456")

	ctx := authorization.WithAuthContext(context.Background(), expectedAuthCtx)
	checker := &internal.MockAuthorizationChecker{Ctx: expectedAuthCtx}
	interceptor := middleware.New(checker)

	retrievedAuthCtx := interceptor.Context(ctx)

	assert.Equal(t, expectedAuthCtx, retrievedAuthCtx)
	assert.Equal(t, "user-123", retrievedAuthCtx.UserID())
	assert.Equal(t, "org-456", retrievedAuthCtx.OrganizationID())
}
