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

func Context(ctx context.Context) Ctx {
	authCtx, ok := ctx.Value(ctxKey).(Ctx)
	if !ok {
		return &emptyCtx{}
	}
	return authCtx
}

func WithAuthContext[T Ctx](ctx context.Context, c T) context.Context {
	return context.WithValue(ctx, ctxKey, c)
}

type emptyCtx struct{}

func (e *emptyCtx) IsAuthorized() bool {
	return false
}

func (e *emptyCtx) IsGrantedRole(_ string) bool {
	return false
}

func (e *emptyCtx) IsGrantedRoleForOrganization(_, _ string) bool {
	return false
}
