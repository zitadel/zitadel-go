package authentication

import (
	"context"
	"net/http"
)

type Interceptor[T Ctx] struct {
	authenticator *Authenticator[T]
}

func Middleware[T Ctx](authenticator *Authenticator[T]) *Interceptor[T] {
	return &Interceptor[T]{
		authenticator: authenticator,
	}
}

// RequireAuthentication will check if there is a valid session and provide it in the context.
// If there is no session, it will automatically start a new authentication (by redirecting the user to the Login UI)
func (i *Interceptor[T]) RequireAuthentication() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx, err := i.authenticator.IsAuthenticated(req)
			if err != nil {
				i.authenticator.Authenticate(w, req, req.RequestURI)
				return
			}
			req = req.WithContext(WithAuthContext(req.Context(), ctx))
			next.ServeHTTP(w, req)
		})
	}
}

// CheckAuthentication will check if there is a valid session and provide it in the context.
// Unlike [RequireAuthentication] it will not start a new authentication if there is none.
func (i *Interceptor[T]) CheckAuthentication() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx, err := i.authenticator.IsAuthenticated(req)
			if err == nil {
				req = req.WithContext(WithAuthContext(req.Context(), ctx))
			}
			next.ServeHTTP(w, req)
		})
	}
}

func (i *Interceptor[T]) Context(ctx context.Context) T {
	return Context[T](ctx)
}
