package authentication

import "context"

type key int

const (
	ctxKey key = 1
)

// Ctx represents the authentication context with information about the authenticated user.
type Ctx interface {
	IsAuthenticated() bool
}

// Context returns a typed implementation the authentication context [Ctx].
// It can be used to get information about the (authenticated) user.
func Context[T Ctx](ctx context.Context) (t T) {
	authCtx, ok := ctx.Value(ctxKey).(T)
	if !ok {
		return t
	}
	return authCtx
}

// IsAuthenticated returns if the user is authenticated
func IsAuthenticated(ctx context.Context) bool {
	authCtx := Context[Ctx](ctx)
	if authCtx == nil {
		return false
	}
	return authCtx.IsAuthenticated()
}

// WithAuthContext allows to set the authentication context ([Ctx]), which can later be retrieved
// by calling the [Context] function.
func WithAuthContext[T Ctx](ctx context.Context, c T) context.Context {
	return context.WithValue(ctx, ctxKey, c)
}
