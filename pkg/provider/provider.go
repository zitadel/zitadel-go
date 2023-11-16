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
	oidc *oidcProvider[*oidc.IDTokenClaims, *oidc.IntrospectionResponse]
}

type AuthenticationProvider interface {
	AuthenticationHandler() http.Handler
	AuthenticationCallbackHandler(redirectURL string) http.Handler
}

type AuthenticationInterceptor interface {
	AuthenticatedHTTPInterceptor() func(next http.Handler) http.Handler
	AuthenticatedUnaryInterceptor() grpc.UnaryServerInterceptor
	AuthenticatedStreamInterceptor() grpc.StreamServerInterceptor
}
type AuthorizationInterceptor[R any] interface {
	AuthenticationHandler() http.Handler
	AuthenticationCallbackHandler(redirectURL string) http.Handler
	AuthorizedHTTPInterceptor(check Check[R]) func(next http.Handler) http.Handler
}

func New(ctx context.Context, conf *configuration) (*Provider, error) {
	if conf.oidc != nil {
		p, err := NewOIDC[*oidc.IDTokenClaims, *oidc.IntrospectionResponse](ctx, conf.oidc)
		if err != nil {
			return nil, err
		}
		return &Provider{
			oidc: p,
		}, nil
	}
	return nil, fmt.Errorf("not supported")
}

func (p *Provider) AuthenticationHandler() http.Handler {
	if p.oidc != nil {
		return p.oidc.AuthenticationHandler()
	}
	return nil
}

func (p *Provider) AuthenticationCallbackHandler(redirectURL string) http.Handler {
	if p.oidc != nil {
		return p.oidc.AuthenticationCallbackHandler(redirectURL)
	}
	return nil
}

func (p *Provider) AuthenticatedHTTPInterceptor() func(next http.Handler) http.Handler {
	if p.oidc != nil {
		return p.oidc.AuthenticatedHTTPInterceptor()
	}
	return nil
}

func (p *Provider) AuthorizedHTTPInterceptor(check Check[*oidc.IntrospectionResponse]) func(next http.Handler) http.Handler {
	if p.oidc != nil {
		return p.oidc.AuthorizedHTTPInterceptor(check)
	}
	return nil
}

func (p *Provider) AuthenticatedUnaryInterceptor() grpc.UnaryServerInterceptor {
	if p.oidc != nil {
		return p.oidc.AuthenticatedUnaryInterceptor()
	}
	return nil
}

func (p *Provider) AuthenticatedStreamInterceptor() grpc.StreamServerInterceptor {
	if p.oidc != nil {
		return p.oidc.AuthenticatedStreamInterceptor()
	}
	return nil
}

type oidcProvider[U rp.SubjectGetter, R any] struct {
	resourceServer     rs.ResourceServer
	relayingParty      rp.RelyingParty
	userinfoCache      Cache[string, U]
	introspectionCache Cache[string, R]
	getToken           func(*http.Request) (string, error)
	setToken           func(http.ResponseWriter, string)
}

var (
	_ AuthenticationProvider                                = &oidcProvider[*oidc.IDTokenClaims, *oidc.IntrospectionResponse]{}
	_ AuthenticationInterceptor                             = &oidcProvider[*oidc.IDTokenClaims, *oidc.IntrospectionResponse]{}
	_ AuthorizationInterceptor[*oidc.IntrospectionResponse] = &oidcProvider[*oidc.IDTokenClaims, *oidc.IntrospectionResponse]{}
)

func NewOIDC[U rp.SubjectGetter, R any](ctx context.Context, conf *configurationOIDC) (_ *oidcProvider[U, R], err error) {
	var resourceServer rs.ResourceServer
	if conf.validRS() {
		resourceServer, err = newResourceServer(ctx, conf)
		if err != nil {
			return nil, err
		}
	}
	var relayingParty rp.RelyingParty
	if conf.validRP() {
		relayingParty, err = newRelayingPartyOIDC(ctx, conf)
		if err != nil {
			return nil, err
		}
	}

	var getToken func(*http.Request) (string, error)
	if conf.authCookie {
		getToken = getTokenFromCookie
	} else {
		getToken = getTokenFromRequest
	}
	var setToken func(w http.ResponseWriter, value string)
	if conf.authCookie {
		setToken = setTokenToCookieFunc("", "", 0)
	} else {
		setToken = setTokenToHeader
	}

	return &oidcProvider[U, R]{
		resourceServer:     resourceServer,
		relayingParty:      relayingParty,
		getToken:           getToken,
		setToken:           setToken,
		userinfoCache:      &EmptyCache[string, U]{},
		introspectionCache: &EmptyCache[string, R]{},
	}, nil
}

func (p *oidcProvider[U, R]) AuthenticationHandler() http.Handler {
	if p.relayingParty != nil {
		return rp.AuthURLHandler(uuid.New().String, p.relayingParty)
	}
	return nil
}

func (p *oidcProvider[U, R]) AuthenticationCallbackHandler(redirectURL string) http.Handler {
	if p.relayingParty != nil {
		return rp.CodeExchangeHandler(redirectCallback(p.setToken, redirectURL), p.relayingParty)
	}
	return nil
}

func (p *oidcProvider[U, R]) AuthenticatedHTTPInterceptor() func(next http.Handler) http.Handler {
	if p.relayingParty != nil {
		return oidcAuthenticatedHTTPInterceptor[U](p.userinfoCache, p.relayingParty)
	}
	return nil
}

func (p *oidcProvider[U, R]) AuthorizedHTTPInterceptor(check Check[R]) func(next http.Handler) http.Handler {
	if p.resourceServer != nil {
		return oidcAuthorizedHTTPInterceptor[R](p.getToken, p.introspectionCache, p.resourceServer, check)
	}
	return nil
}

func (p *oidcProvider[U, R]) AuthenticatedUnaryInterceptor() grpc.UnaryServerInterceptor {
	if p.relayingParty != nil {
		return oidcAuthenticatedUnaryInterceptor[U](p.userinfoCache, p.relayingParty)
	}
	return nil
}

func (p *oidcProvider[U, R]) AuthenticatedStreamInterceptor() grpc.StreamServerInterceptor {
	if p.relayingParty != nil {
		return oidcAuthenticatedStreamInterceptor[U](p.userinfoCache, p.relayingParty)
	}
	return nil
}
