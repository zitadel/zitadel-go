package oidc

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	http2 "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v2/pkg/authentication"
)

type Ctx interface {
	authentication.Ctx
	oidc.IDClaims
	rp.SubjectGetter
}

type CodeFlowAuthentication[T Ctx] struct {
	rp.RelyingParty
}

func WithCodeFlow[T Ctx](auth ClientAuthentication) authentication.AuthenticationProviderInitializer[T] {
	return func(ctx context.Context, domain string) (authentication.AuthenticationProvider[T], error) {
		relyingParty, err := auth(ctx, domain)
		if err != nil {
			return nil, err
		}
		return &CodeFlowAuthentication[T]{
			RelyingParty: relyingParty,
		}, nil
	}
}

type ClientAuthentication func(ctx context.Context, domain string) (rp.RelyingParty, error)

func PKCEAuthentication(clientID, redirectURI string, cookieHandler *http2.CookieHandler) ClientAuthentication {
	return func(ctx context.Context, domain string) (rp.RelyingParty, error) {
		return rp.NewRelyingPartyOIDC(ctx, domain, clientID, "", redirectURI, []string{"openid", "profile", "email"}, rp.WithPKCE(cookieHandler))
	}
}

func ClientIDSecretAuthentication(clientID, clientSecret string) ClientAuthentication {
	return func(ctx context.Context, domain string) (rp.RelyingParty, error) {
		return rp.NewRelyingPartyOIDC(ctx, domain, clientID, clientSecret, "redirectURI", []string{"openid"})
	}
}

func (c *CodeFlowAuthentication[T]) Authenticate(state string) http.HandlerFunc {
	return rp.AuthURLHandler(func() string {
		return state
	}, c.RelyingParty)
}

func (c *CodeFlowAuthentication[T]) Callback(w http.ResponseWriter, r *http.Request) (t T, state string) {
	rp.CodeExchangeHandler[T](rp.UserinfoCallback[T, T](func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[T], callbackState string, provider rp.RelyingParty, info T) {
		slog.Info("callback", "at", tokens.AccessToken, "state", callbackState, "info", info)
		t = info
		state = callbackState
	}), c.RelyingParty)(w, r)
	return t, state
}

func (c *CodeFlowAuthentication[T]) Logout(ctx context.Context, idToken, state string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		url, err := rp.EndSession(ctx, c.RelyingParty, idToken, "", state)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, req, url.String(), http.StatusFound)
	}
}
