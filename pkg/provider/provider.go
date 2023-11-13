package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/client/rs"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"google.golang.org/grpc"
)

type Provider struct {
	oidc *oidcProvider
}

type oidcProvider struct {
	resourceServer rs.ResourceServer
	relayingParty  rp.RelyingParty
}

func New(ctx context.Context, conf *configuration) (_ *Provider, err error) {
	if conf.oidc != nil {

		var resourceServer rs.ResourceServer
		if conf.oidc.validRS() {
			resourceServer, err = newResourceServer(ctx, conf.oidc)
			if err != nil {
				return nil, err
			}
		}
		var relayingParty rp.RelyingParty
		if conf.oidc.validRP() {
			relayingParty, err = newRelayingPartyOIDC(ctx, conf.oidc)
			if err != nil {
				return nil, err
			}
		}
		return &Provider{
			oidc: &oidcProvider{
				resourceServer: resourceServer,
				relayingParty:  relayingParty,
			},
		}, nil
	}
	return nil, fmt.Errorf("not supported")
}

func (p *Provider) AuthenticationHandler() http.Handler {
	if p.oidc != nil && p.oidc.relayingParty != nil {
		return rp.AuthURLHandler(uuid.New().String, p.oidc.relayingParty)
	}
	return nil
}

func (p *Provider) AuthenticationCallbackHandler(redirectURL string) http.Handler {
	if p.oidc != nil && p.oidc.relayingParty != nil {
		return rp.CodeExchangeHandler(redirectCallback[*oidc.IDTokenClaims](redirectURL), p.oidc.relayingParty)
	}
	return nil
}

func (p *Provider) AuthenticatedHTTPInterceptor() func(next http.Handler) http.Handler {
	if p.oidc != nil && p.oidc.relayingParty != nil {
		return oidcAuthenticatedHTTPInterceptor[*oidc.IDTokenClaims](&EmptyCache[string, *oidc.IDTokenClaims]{}, p.oidc.relayingParty)
	}
	return nil
}

func (p *Provider) AuthorizedHTTPInterceptor(check Check[*oidc.IntrospectionResponse]) func(next http.Handler) http.Handler {
	if p.oidc != nil && p.oidc.resourceServer != nil {
		return oidcAuthorizedHTTPInterceptor[*oidc.IntrospectionResponse](&EmptyCache[string, *oidc.IntrospectionResponse]{}, p.oidc.resourceServer, check)
	}
	return nil
}

func (p *Provider) AuthenticatedUnaryInterceptor() grpc.UnaryServerInterceptor {
	if p.oidc != nil && p.oidc.relayingParty != nil {
		return oidcAuthenticatedUnaryInterceptor[*oidc.IDTokenClaims](&EmptyCache[string, *oidc.IDTokenClaims]{}, p.oidc.relayingParty)
	}
	return nil
}

func (p *Provider) AuthenticatedStreamInterceptor() grpc.StreamServerInterceptor {
	if p.oidc != nil && p.oidc.relayingParty != nil {
		return oidcAuthenticatedStreamInterceptor[*oidc.IDTokenClaims](&EmptyCache[string, *oidc.IDTokenClaims]{}, p.oidc.relayingParty)
	}
	return nil
}
