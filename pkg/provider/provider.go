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

var (
	key = []byte("test1234test1234")
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

func (p *Provider) AuthenticationCallbackHandler(redirect rp.CodeExchangeCallback[oidc.IDClaims]) http.Handler {
	if p.oidc != nil && p.oidc.relayingParty != nil {
		return rp.CodeExchangeHandler(redirect, p.oidc.relayingParty)
	}
	return nil
}

func (p *Provider) AuthenticatedHTTPInterceptor() func(next http.Handler) http.Handler {
	if p.oidc != nil && p.oidc.resourceServer != nil {
		return oidcAuthenticatedHTTPInterceptor(p.oidc.resourceServer)
	}
	return nil
}

func (p *Provider) AuthorizedHTTPInterceptor(requestedClaim, requestedValue string) func(next http.Handler) http.Handler {
	if p.oidc != nil && p.oidc.resourceServer != nil {
		return oidcAuthorizedHTTPInterceptor(p.oidc.resourceServer, requestedClaim, requestedValue)
	}
	return nil
}

func (p *Provider) AuthenticatedUnaryInterceptor() grpc.UnaryServerInterceptor {
	if p.oidc != nil && p.oidc.resourceServer != nil {
		return oidcAuthenticatedUnaryInterceptor(p.oidc.resourceServer)
	}
	return nil
}

func (p *Provider) AuthenticatedUnaryStreamInterceptor() grpc.StreamServerInterceptor {
	if p.oidc != nil && p.oidc.resourceServer != nil {
		return oidcAuthenticatedStreamInterceptor(p.oidc.resourceServer)
	}
	return nil
}