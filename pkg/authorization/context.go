package authorization

import "context"

type key int

const (
	ctxKey key = 1
)

// Ctx represents the authorization context with information about the authorized user.
type Ctx interface {
	IsAuthorized() bool
	UserID() string
	IsGrantedRole(role string) bool
	IsGrantedRoleInOrganization(role, organizationID string) bool
	SetToken(token string)
	GetToken() string
}

// Context returns a typed implementation the authorization context [Ctx].
// It can be used to get information about the (authorized) user / caller.
func Context[T Ctx](ctx context.Context) (t T) {
	authCtx, ok := ctx.Value(ctxKey).(T)
	if !ok {
		return t
	}
	return authCtx
}

// IsAuthorized returns if the caller is authorized
func IsAuthorized(ctx context.Context) bool {
	return Context[Ctx](ctx).IsAuthorized()
}

// UserID returns if the ID of the authorized user.
// In case of an unauthorized caller, the id is empty.
func UserID(ctx context.Context) string {
	return Context[Ctx](ctx).UserID()
}

// IsGrantedRole returns if the authorized user is granted the requested role.
// In case of an unauthorized caller, the returned value is false.
func IsGrantedRole(ctx context.Context, role string) bool {
	return Context[Ctx](ctx).IsGrantedRole(role)
}

// IsGrantedRoleInOrganization returns if the authorized user is granted the requested role in the specified organisation.
// In case of an unauthorized caller, the returned value is false.
func IsGrantedRoleInOrganization(ctx context.Context, role, organisationID string) bool {
	return Context[Ctx](ctx).IsGrantedRoleInOrganization(role, organisationID)
}

// WithAuthContext allows to set the authorization context ([Ctx]), which can later be retrieved
// by calling the [Context] function.
func WithAuthContext[T Ctx](ctx context.Context, c T) context.Context {
	return context.WithValue(ctx, ctxKey, c)
}
