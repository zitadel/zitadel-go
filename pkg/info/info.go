package info

import (
	"context"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

type userinfoKey struct{}

func UserinfoFromContext[U rp.SubjectGetter](ctx context.Context) U {
	var unil U
	m := ctx.Value(userinfoKey{})
	if m == nil {
		return unil
	}
	i, ok := m.(U)
	if !ok {
		return unil
	}
	return i
}

func UserinfoIntoContext[U rp.SubjectGetter](ctx context.Context, i U) context.Context {
	return context.WithValue(ctx, userinfoKey{}, i)
}

type introspectionKey struct{}

func IntrospectionFromContext[R any](ctx context.Context) R {
	var rnil R
	m := ctx.Value(introspectionKey{})
	if m == nil {
		return rnil
	}
	i, ok := m.(R)
	if !ok {
		return rnil
	}
	return i
}

func IntrospectionIntoContext[R any](ctx context.Context, i R) context.Context {
	return context.WithValue(ctx, introspectionKey{}, i)
}
