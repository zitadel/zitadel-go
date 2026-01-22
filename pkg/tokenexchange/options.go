package tokenexchange

import (
	"context"
	"net/http"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/client/tokenexchange"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// UserIDTokenType is a ZITADEL-specific token type that allows impersonation
// by user ID instead of requiring an existing token for the user.
// This is an experimental ZITADEL extension and may not be supported by
// other OAuth 2.0 providers.
const UserIDTokenType oidc.TokenType = "urn:zitadel:params:oauth:token-type:user_id"

type config struct {
	subjectTokenType   oidc.TokenType
	actorTokenType     oidc.TokenType
	scopes             []string
	audience           []string
	resource           []string
	requestedTokenType oidc.TokenType
	clientAuth         ClientAuth
}

// Option configures a token exchange request.
type Option func(*config)

// ClientAuth provides client authentication for token exchange requests.
// Use [ClientCredentials] or [JWTProfile] to create an instance.
type ClientAuth interface {
	createExchanger(ctx context.Context, issuer string, httpClient *http.Client) (tokenexchange.TokenExchanger, error)
}

type clientCredentialsAuth struct {
	clientID     string
	clientSecret string
}

func (c *clientCredentialsAuth) createExchanger(ctx context.Context, issuer string, httpClient *http.Client) (tokenexchange.TokenExchanger, error) {
	return tokenexchange.NewTokenExchangerClientCredentials(
		ctx,
		issuer,
		c.clientID,
		c.clientSecret,
		tokenexchange.WithHTTPClient(httpClient),
	)
}

// ClientCredentials returns a ClientAuth that uses client_id and client_secret
// for authentication via HTTP Basic Auth.
func ClientCredentials(clientID, clientSecret string) ClientAuth {
	return &clientCredentialsAuth{
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

type jwtProfileAuth struct {
	clientID string
	signer   jose.Signer
}

func (j *jwtProfileAuth) createExchanger(ctx context.Context, issuer string, httpClient *http.Client) (tokenexchange.TokenExchanger, error) {
	return tokenexchange.NewTokenExchangerJWTProfile(
		ctx,
		issuer,
		j.clientID,
		j.signer,
		tokenexchange.WithHTTPClient(httpClient),
	)
}

// JWTProfile returns a ClientAuth that uses JWT assertion for authentication.
// The signer should be created from the application's private key.
func JWTProfile(clientID string, signer jose.Signer) ClientAuth {
	return &jwtProfileAuth{
		clientID: clientID,
		signer:   signer,
	}
}

// WithClientAuth sets the client authentication method for the token exchange.
// Token exchange requests require client authentication. Use [ClientCredentials]
// or [JWTProfile] to create the auth provider.
func WithClientAuth(auth ClientAuth) Option {
	return func(cfg *config) {
		cfg.clientAuth = auth
	}
}

// SubjectIsUserID indicates the subject token is a ZITADEL user ID.
// This is a ZITADEL-specific extension that allows impersonation without
// requiring an existing token for the target user.
func SubjectIsUserID() Option {
	return func(cfg *config) {
		cfg.subjectTokenType = UserIDTokenType
	}
}

// SubjectIsAccessToken indicates the subject token is an access token.
// This is the default if no subject token type is specified.
func SubjectIsAccessToken() Option {
	return func(cfg *config) {
		cfg.subjectTokenType = oidc.AccessTokenType
	}
}

// SubjectIsIDToken indicates the subject token is an ID token.
func SubjectIsIDToken() Option {
	return func(cfg *config) {
		cfg.subjectTokenType = oidc.IDTokenType
	}
}

// SubjectIsJWT indicates the subject token is a self-signed JWT.
func SubjectIsJWT() Option {
	return func(cfg *config) {
		cfg.subjectTokenType = oidc.JWTTokenType
	}
}

// ActorIsAccessToken indicates the actor token is an access token.
// This is the default if no actor token type is specified.
func ActorIsAccessToken() Option {
	return func(cfg *config) {
		cfg.actorTokenType = oidc.AccessTokenType
	}
}

// ActorIsIDToken indicates the actor token is an ID token.
func ActorIsIDToken() Option {
	return func(cfg *config) {
		cfg.actorTokenType = oidc.IDTokenType
	}
}

// WithScopes sets the scopes to request for the exchanged token.
func WithScopes(scopes ...string) Option {
	return func(cfg *config) {
		cfg.scopes = scopes
	}
}

// WithAudience sets the audience for the exchanged token.
func WithAudience(audiences ...string) Option {
	return func(cfg *config) {
		cfg.audience = audiences
	}
}

// WithResource sets the resource parameter for the exchanged token.
// This indicates the target service or API where the token will be used.
func WithResource(resources ...string) Option {
	return func(cfg *config) {
		cfg.resource = resources
	}
}

// WithRequestedTokenType sets the type of token to request.
// Use oidc.AccessTokenType for an opaque access token (default),
// or oidc.JWTTokenType for a JWT access token.
func WithRequestedTokenType(tokenType oidc.TokenType) Option {
	return func(cfg *config) {
		cfg.requestedTokenType = tokenType
	}
}
