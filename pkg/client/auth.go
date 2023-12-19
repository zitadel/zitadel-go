package client

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/profile"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
)

type TokenSourceInitializer func(ctx context.Context, issuer string) (oauth2.TokenSource, error)

// JWTAuthentication allows using the OAuth2 JWT Profile Grant to get a token using a key.json of a service user provided by ZITADEL.
func JWTAuthentication(file *client.KeyFile, scopes ...string) TokenSourceInitializer {
	return func(ctx context.Context, issuer string) (oauth2.TokenSource, error) {
		return profile.NewJWTProfileTokenSource(ctx, issuer, file.UserID, file.KeyID, []byte(file.Key), scopes)
	}
}

// PasswordAuthentication allows using the OAuth2 Client Credentials Grant to get a token using username and password
// of a service user provided by ZITADEL.
func PasswordAuthentication(username, password string, scopes ...string) TokenSourceInitializer {
	return func(ctx context.Context, issuer string) (oauth2.TokenSource, error) {
		discovery, err := client.Discover(ctx, issuer, http.DefaultClient)
		if err != nil {
			return nil, err
		}
		config := &clientcredentials.Config{
			ClientID:     username,
			ClientSecret: password,
			TokenURL:     discovery.TokenEndpoint,
			Scopes:       scopes,
		}
		return config.TokenSource(ctx), nil
	}
}

// PAT allows setting a service user personal access token to be used for authorization.
func PAT(pat string) TokenSourceInitializer {
	return func(ctx context.Context, _ string) (oauth2.TokenSource, error) {
		return oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: pat,
			TokenType:   oidc.BearerToken,
		}), nil
	}
}

// DefaultServiceUserAuthentication is a short version of [JWTAuthentication]
// with a key.json read from a provided path.
func DefaultServiceUserAuthentication(path string, scopes ...string) TokenSourceInitializer {
	c, err := client.ConfigFromKeyFile(path)
	if err != nil {
		return func(ctx context.Context, issuer string) (oauth2.TokenSource, error) {
			return nil, err
		}
	}
	return JWTAuthentication(c, scopes...)
}

// AuthorizedUserCtx will set the authorization token of the authorized context (user) to be used
// for a subsequent call. If there is no authorized context, the method will simply return the passed context back.
func AuthorizedUserCtx(ctx context.Context) context.Context {
	authCtx := authorization.Context[authorization.Ctx](ctx)
	if !authCtx.IsAuthorized() {
		return ctx
	}
	return BearerTokenCtx(ctx, strings.TrimPrefix(authCtx.GetToken(), oidc.BearerToken))
}

// BearerTokenCtx will set the passed token to be used for a subsequent call.
func BearerTokenCtx(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, ctxOverwrite, &oauth2.Token{
		AccessToken: strings.Trim(token, " "),
		TokenType:   oidc.BearerToken,
	})
}

const (
	scopeFormatProjectID  = "urn:zitadel:iam:org:project:id:%s:aud"
	scopeZITADELProjectID = "zitadel"
)

// ScopeProjectID will add the requested projectID to the audience of the access and id token
func ScopeProjectID(projectID string) string {
	return fmt.Sprintf(scopeFormatProjectID, projectID)
}

// ScopeZitadelAPI adds the projectID of ZITADEL to the audience
func ScopeZitadelAPI() string {
	return ScopeProjectID(scopeZITADELProjectID)
}
