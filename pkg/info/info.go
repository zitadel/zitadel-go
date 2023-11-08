package info

import (
	"context"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type providerInfoKey struct{}

type ProviderInfo struct {
	IntrospectionResponse *oidc.IntrospectionResponse
}

func (p *ProviderInfo) IntoContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, providerInfoKey{}, p)
}

func ProviderInfoFromContext(ctx context.Context) *ProviderInfo {
	m := ctx.Value(providerInfoKey{})
	if m == nil {
		return &ProviderInfo{}
	}
	pi, ok := m.(*ProviderInfo)
	if !ok {
		return &ProviderInfo{}
	}
	return pi
}

func (p *ProviderInfo) SetIntrospectionResponse(resp *oidc.IntrospectionResponse) *ProviderInfo {
	p.IntrospectionResponse = resp
	return p
}
