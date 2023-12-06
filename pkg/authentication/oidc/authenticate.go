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

// CodeFlowAuthentication provides an [authentication.Handler] implementation with
// an OIDC/OAuth2 Authorization Code Flow.
// Use [WithCodeFlow] for implementation.
type CodeFlowAuthentication[T Ctx[C, S], C oidc.IDClaims, S rp.SubjectGetter] struct {
	relyingParty rp.RelyingParty
}

// WithCodeFlow creates the OIDC/OAuth2 Authorization Code Flow implementation of the [authentication.Handler] interface.
// The token endpoint itself requires some [ClientAuthentication] of the client.
// Possible implementation are [PKCEAuthentication] and [ClientIDSecretAuthentication].
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

// PKCEAuthentication allows to authenticate the code exchange request with Proof Key of Code Exchange (PKCE).
func PKCEAuthentication(clientID, redirectURI string, scopes []string, cookieHandler *http2.CookieHandler) ClientAuthentication {
	return func(ctx context.Context, domain string) (rp.RelyingParty, error) {
		return newRP(ctx, domain, clientID, "", redirectURI, scopes, rp.WithPKCE(cookieHandler))
	}
}

// ClientIDSecretAuthentication allows to authenticate the code exchange request with client_id and client_secret provide by ZITADEL.
func ClientIDSecretAuthentication(clientID, clientSecret, redirectURI string, scopes []string, cookieHandler *http2.CookieHandler) ClientAuthentication {
	return func(ctx context.Context, domain string) (rp.RelyingParty, error) {
		return newRP(ctx, domain, clientID, clientSecret, redirectURI, scopes, rp.WithCookieHandler(cookieHandler))
	}
}

// DefaultAuthentication is a short version of [WithCodeFlow[*UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo], *oidc.IDTokenClaims, *oidc.UserInfo]]
// with the client_id, redirectURI and encryptionKey and optional scopes.
// If no scopes are provided, `"openid", "profile", "email"` will be used.
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

// Authenticate starts the OIDC/OAuth2 Authorization Code Flow and redirects the user to the Login UI.
func (c *CodeFlowAuthentication[T, C, S]) Authenticate(w http.ResponseWriter, r *http.Request, state string) {
	rp.AuthURLHandler(func() string { return state }, c.relyingParty)(w, r)
}

// Callback handles the redirect back from the Login UI and will exchange the code for the tokens.
// Additionally, it will retrieve the information from the userinfo_endpoint and store everything in the [Ctx].
func (c *CodeFlowAuthentication[T, C, S]) Callback(w http.ResponseWriter, r *http.Request) (authCtx T, state string) {
	rp.CodeExchangeHandler[C](rp.UserinfoCallback[C, S](func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[C], callbackState string, provider rp.RelyingParty, info S) {
		state = callbackState
		authCtx = authCtx.New().(T)
		authCtx.SetTokens(tokens)
		authCtx.SetUserInfo(info)
	}), c.relyingParty)(w, r)
	return authCtx, state
}

// Logout will call the end_session_endpoint at the Authorization Server (Login UI).
func (c *CodeFlowAuthentication[T, C, S]) Logout(w http.ResponseWriter, r *http.Request, authCtx T, state, optionalRedirectURI string) {
	url, err := rp.EndSession(r.Context(), c.relyingParty, authCtx.GetTokens().IDToken, optionalRedirectURI, state)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, url.String(), http.StatusFound)
}
