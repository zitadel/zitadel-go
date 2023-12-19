package oidc

import (
	"context"
	"net/http"
	"net/url"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/authentication"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

type Ctx[C oidc.IDClaims, S rp.SubjectGetter] interface {
	authentication.Ctx
	New() Ctx[C, S]
	SetTokens(*oidc.Tokens[C])
	GetTokens() *oidc.Tokens[C]
	SetUserInfo(S)
	GetUserInfo() S
}

// codeFlowAuthentication provides an [authentication.Handler] implementation with
// an OIDC/OAuth2 Authorization Code Flow.
// Use [WithCodeFlow] for implementation.
type codeFlowAuthentication[T Ctx[C, S], C oidc.IDClaims, S rp.SubjectGetter] struct {
	relyingParty rp.RelyingParty
}

// WithCodeFlow creates the OIDC/OAuth2 Authorization Code Flow implementation of the [authentication.Handler] interface.
// The token endpoint itself requires some [ClientAuthentication] of the client.
// Possible implementation are [PKCEAuthentication] and [ClientIDSecretAuthentication].
func WithCodeFlow[T Ctx[C, S], C oidc.IDClaims, S rp.SubjectGetter](auth ClientAuthentication) authentication.HandlerInitializer[T] {
	return func(ctx context.Context, zitadel *zitadel.Zitadel) (authentication.Handler[T], error) {
		relyingParty, err := auth(ctx, zitadel.Origin())
		if err != nil {
			return nil, err
		}
		return &codeFlowAuthentication[T, C, S]{
			relyingParty: relyingParty,
		}, nil
	}
}

type ClientAuthentication func(ctx context.Context, domain string) (rp.RelyingParty, error)

// PKCEAuthentication allows to authenticate the code exchange request with Proof Key of Code Exchange (PKCE).
func PKCEAuthentication(clientID, redirectURI string, scopes []string, cookieHandler *httphelper.CookieHandler) ClientAuthentication {
	return func(ctx context.Context, domain string) (rp.RelyingParty, error) {
		return newRP(ctx, domain, clientID, "", redirectURI, scopes, rp.WithPKCE(cookieHandler))
	}
}

// ClientIDSecretAuthentication allows to authenticate the code exchange request with client_id and client_secret provide by ZITADEL.
func ClientIDSecretAuthentication(clientID, clientSecret, redirectURI string, scopes []string, cookieHandler *httphelper.CookieHandler) ClientAuthentication {
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
		PKCEAuthentication(clientID, redirectURI, scopes, httphelper.NewCookieHandler([]byte(key), []byte(key))),
	)
}

func newRP(ctx context.Context, domain, clientID, clientSecret, redirectURI string, scopes []string, options ...rp.Option) (rp.RelyingParty, error) {
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID}
	}
	return rp.NewRelyingPartyOIDC(ctx, domain, clientID, clientSecret, redirectURI, scopes, options...)
}

// Authenticate starts the OIDC/OAuth2 Authorization Code Flow and redirects the user to the Login UI.
func (c *codeFlowAuthentication[T, C, S]) Authenticate(w http.ResponseWriter, r *http.Request, state string) {
	rp.AuthURLHandler(func() string { return state }, c.relyingParty)(w, r)
}

// Callback handles the redirect back from the Login UI and will exchange the code for the tokens.
// Additionally, it will retrieve the information from the userinfo_endpoint and store everything in the [Ctx].
func (c *codeFlowAuthentication[T, C, S]) Callback(w http.ResponseWriter, r *http.Request) (authCtx T, state string) {
	rp.CodeExchangeHandler[C](rp.UserinfoCallback[C, S](func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[C], callbackState string, provider rp.RelyingParty, info S) {
		state = callbackState
		authCtx = authCtx.New().(T)
		authCtx.SetTokens(tokens)
		authCtx.SetUserInfo(info)
	}), c.relyingParty)(w, r)
	return authCtx, state
}

// Logout will call, resp. redirect to the end_session_endpoint at the Authorization Server (Login UI).
func (c *codeFlowAuthentication[T, C, S]) Logout(w http.ResponseWriter, r *http.Request, authCtx T, state, optionalRedirectURI string) {
	// the OIDC library currently does a server side POST request, but the spec. requires a browser call
	// and esp. ZITADEL requires the "user agent" cookie present to be able to terminate the session(s).
	//
	// The current implementation of the library was done when the spec was still in draft.
	// However, in the meantime the spec was updated with more parameters and published.
	// Until the library is updated to the current standard, we will implement the library's
	// current request (same parameters) as redirect here.
	req := oidc.EndSessionRequest{
		IdTokenHint:           authCtx.GetTokens().IDToken,
		ClientID:              c.relyingParty.OAuthConfig().ClientID,
		PostLogoutRedirectURI: optionalRedirectURI,
		State:                 state,
	}
	endSession, err := url.Parse(c.relyingParty.GetEndSessionEndpoint())
	if err != nil {
		http.Error(w, "failed to build end session endpoint: "+err.Error(), http.StatusInternalServerError)
		return
	}
	params, err := httphelper.URLEncodeParams(req, client.Encoder)
	if err != nil {
		http.Error(w, "failed to build end session parameters: "+err.Error(), http.StatusInternalServerError)
		return
	}
	endSession.RawQuery = params.Encode()
	http.Redirect(w, r, endSession.String(), http.StatusFound)
}
