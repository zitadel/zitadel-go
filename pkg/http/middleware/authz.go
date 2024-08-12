package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
)

type Interceptor[T authorization.Ctx] struct {
	authorizer *authorization.Authorizer[T]
}

func New[T authorization.Ctx](authorizer *authorization.Authorizer[T]) *Interceptor[T] {
	return &Interceptor[T]{
		authorizer: authorizer,
	}
}

func (i *Interceptor[T]) RequireAuthorization(options ...authorization.CheckOption) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx, err := i.authorizer.CheckAuthorization(req.Context(), req.Header.Get(authorization.HeaderName), options...)
			if err != nil {
				if errors.Is(err, &authorization.UnauthorizedErr{}) {
					http.Error(w, err.Error(), http.StatusUnauthorized)
					return
				}
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			req = req.WithContext(authorization.WithAuthContext(req.Context(), ctx))
			next.ServeHTTP(w, req)
		})
	}
}

func (i *Interceptor[T]) Context(ctx context.Context) T {
	return authorization.Context[T](ctx)
}
