package oidc

import (
	"context"
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	http2 "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/authentication"
)

type Ctx[C oidc.IDClaims, S rp.SubjectGetter] interface {
	authentication.Ctx
	New() Ctx[C, S]
	SetTokens(*oidc.Tokens[C])
	GetTokens() *oidc.Tokens[C]
	SetUserInfo(S)
	GetUserInfo() S
}

type CodeFlowAuthentication[T Ctx[C, S], C oidc.IDClaims, S rp.SubjectGetter] struct {
	relyingParty rp.RelyingParty
}

func WithCodeFlow[T Ctx[C, S], C oidc.IDClaims, S rp.SubjectGetter](auth ClientAuthentication) authentication.HandlerInitializer[T] {
	return func(ctx context.Context, domain string) (authentication.Handler[T], error) {
		relyingParty, err := auth(ctx, domain)
		if err != nil {
			return nil, err
		}
		return &CodeFlowAuthentication[T, C, S]{
			relyingParty: relyingParty,
		}, nil
	}
}

type ClientAuthentication func(ctx context.Context, domain string) (rp.RelyingParty, error)

func PKCEAuthentication(clientID, redirectURI string, scopes []string, cookieHandler *http2.CookieHandler) ClientAuthentication {
	return func(ctx context.Context, domain string) (rp.RelyingParty, error) {
		return newRP(ctx, domain, clientID, "", redirectURI, scopes, rp.WithPKCE(cookieHandler))
	}
}

func ClientIDSecretAuthentication(clientID, clientSecret, redirectURI string, scopes []string, cookieHandler *http2.CookieHandler) ClientAuthentication {
	return func(ctx context.Context, domain string) (rp.RelyingParty, error) {
		return newRP(ctx, domain, clientID, clientSecret, redirectURI, scopes, rp.WithCookieHandler(cookieHandler))
	}
}

func DefaultAuthentication(clientID, redirectURI string, key string, scopes ...string) authentication.HandlerInitializer[*UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]] {
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail}
	}
	return WithCodeFlow[*UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo], *oidc.IDTokenClaims, *oidc.UserInfo](
		PKCEAuthentication(clientID, redirectURI, scopes, http2.NewCookieHandler([]byte(key), []byte(key))),
	)
}

func newRP(ctx context.Context, domain, clientID, clientSecret, redirectURI string, scopes []string, options ...rp.Option) (rp.RelyingParty, error) {
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID}
	}
	return rp.NewRelyingPartyOIDC(ctx, domain, clientID, clientSecret, redirectURI, scopes, options...)
}

func (c *CodeFlowAuthentication[T, C, S]) Authenticate(w http.ResponseWriter, r *http.Request, state string) {
	rp.AuthURLHandler(func() string { return state }, c.relyingParty)(w, r)
}

func (c *CodeFlowAuthentication[T, C, S]) Callback(w http.ResponseWriter, r *http.Request) (authCtx T, state string) {
	rp.CodeExchangeHandler[C](rp.UserinfoCallback[C, S](func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[C], callbackState string, provider rp.RelyingParty, info S) {
		state = callbackState
		authCtx = authCtx.New().(T)
		authCtx.SetTokens(tokens)
		authCtx.SetUserInfo(info)
	}), c.relyingParty)(w, r)
	return authCtx, state
}

func (c *CodeFlowAuthentication[T, C, S]) Logout(w http.ResponseWriter, r *http.Request, authCtx T, state string) {
	url, err := rp.EndSession(r.Context(), c.relyingParty, authCtx.GetTokens().IDToken, "", state)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, url.String(), http.StatusFound)
}
