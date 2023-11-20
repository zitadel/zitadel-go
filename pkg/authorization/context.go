package authorization

import "context"

type key int

const (
	ctxKey key = 1
)

type Ctx interface {
	IsAuthorized() bool
	IsGrantedRole(role string) bool
	IsGrantedRoleForOrganization(role, organizationID string) bool
}

func Context[T Ctx](ctx context.Context) (t T) {
	authCtx, ok := ctx.Value(ctxKey).(T)
	if !ok {
		return t
	}
	return authCtx
}

func WithAuthContext[T Ctx](ctx context.Context, c T) context.Context {
	return context.WithValue(ctx, ctxKey, c)
}
