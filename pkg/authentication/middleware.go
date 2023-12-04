package authentication

import (
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

func (i *Interceptor[T]) RequireAuthentication() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx, err := i.authenticator.IsAuthenticated(w, req)
			if err != nil {
				i.authenticator.Authenticate(req.RequestURI)(w, req)
				return
			}
			req = req.WithContext(WithAuthContext(req.Context(), ctx))
			next.ServeHTTP(w, req)
		})
	}
}
