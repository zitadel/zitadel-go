package tokenexchange

import (
	"context"
	"errors"

	"github.com/zitadel/oidc/v3/pkg/client/tokenexchange"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/tokenexchange/internal/http"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

// UserIDTokenType is a ZITADEL-specific token type that allows impersonation
// by user ID instead of requiring an existing token for the user.
const UserIDTokenType oidc.TokenType = "urn:zitadel:params:oauth:token-type:user_id"

// Result contains the tokens returned from a token exchange.
type Result struct {
	// AccessToken is the exchanged access token. Depending on WithRequestedTokenType,
	// this may be an opaque token or a JWT.
	AccessToken string

	// TokenType is the type of the access token, typically "Bearer".
	// May be "N_A" if the requested token type was an ID token.
	TokenType string

	// IDToken is the ID token, only present if "openid" scope was requested.
	IDToken string

	// RefreshToken is the refresh token, only present if "offline_access" scope was requested.
	RefreshToken string

	// ExpiresIn is the lifetime of the access token in seconds.
	ExpiresIn int

	// Scopes are the scopes granted to the access token.
	Scopes []string
}

type config struct {
	subjectTokenType   oidc.TokenType
	actorTokenType     oidc.TokenType
	scopes             []string
	audience           []string
	requestedTokenType oidc.TokenType
}

// Option configures a token exchange request.
type Option func(*config)

// SubjectIsUserID indicates the subject token is a ZITADEL user ID.
// This is a ZITADEL-specific extension that allows impersonation without
// requiring an existing token for the target user.
func SubjectIsUserID() Option {
	return func(c *config) {
		c.subjectTokenType = UserIDTokenType
	}
}

// SubjectIsAccessToken indicates the subject token is an access token.
// This is the default if no subject token type is specified.
func SubjectIsAccessToken() Option {
	return func(c *config) {
		c.subjectTokenType = oidc.AccessTokenType
	}
}

// SubjectIsIDToken indicates the subject token is an ID token.
func SubjectIsIDToken() Option {
	return func(c *config) {
		c.subjectTokenType = oidc.IDTokenType
	}
}

// SubjectIsJWT indicates the subject token is a self-signed JWT.
// This is typically used with JWT Profile client authentication.
func SubjectIsJWT() Option {
	return func(c *config) {
		c.subjectTokenType = oidc.JWTTokenType
	}
}

// ActorIsAccessToken indicates the actor token is an access token.
// This is the default if no actor token type is specified.
func ActorIsAccessToken() Option {
	return func(c *config) {
		c.actorTokenType = oidc.AccessTokenType
	}
}

// ActorIsIDToken indicates the actor token is an ID token.
func ActorIsIDToken() Option {
	return func(c *config) {
		c.actorTokenType = oidc.IDTokenType
	}
}

// WithScopes sets the scopes to request for the exchanged token.
// Common scopes include "openid", "profile", "email", "offline_access".
func WithScopes(scopes ...string) Option {
	return func(c *config) {
		c.scopes = scopes
	}
}

// WithAudience sets the audience for the exchanged token.
// The audience must be a subset of the combined audiences from subject and actor tokens.
func WithAudience(audiences ...string) Option {
	return func(c *config) {
		c.audience = audiences
	}
}

// WithRequestedTokenType sets the type of token to request.
// Use oidc.AccessTokenType for an opaque access token (default),
// or oidc.JWTTokenType for a JWT access token.
func WithRequestedTokenType(tokenType oidc.TokenType) Option {
	return func(c *config) {
		c.requestedTokenType = tokenType
	}
}

// Impersonate performs a token exchange to act as another user.
//
// The actorToken must be from a user or service account that has impersonation
// permissions (e.g., ORG_END_USER_IMPERSONATOR or IAM_END_USER_IMPERSONATOR role).
//
// The subjectToken identifies the user to impersonate. Use one of the Subject*
// options to specify the token type:
//   - SubjectIsUserID(): subject is a ZITADEL user ID string
//   - SubjectIsAccessToken(): subject is an access token
//   - SubjectIsIDToken(): subject is an ID token
//   - SubjectIsJWT(): subject is a self-signed JWT
//
// Example:
//
//	result, err := tokenexchange.Impersonate(ctx,
//	    z,
//	    "259242039378444290",
//	    actorToken,
//	    tokenexchange.SubjectIsUserID(),
//	    tokenexchange.WithScopes("openid", "profile"),
//	)
func Impersonate(
	ctx context.Context,
	z *zitadel.Zitadel,
	subjectToken string,
	actorToken string,
	opts ...Option,
) (*Result, error) {
	if subjectToken == "" {
		return nil, errors.New("tokenexchange: subject token is required")
	}
	if actorToken == "" {
		return nil, errors.New("tokenexchange: actor token is required for impersonation")
	}

	cfg := &config{
		subjectTokenType: oidc.AccessTokenType,
		actorTokenType:   oidc.AccessTokenType,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return doExchange(ctx, z, subjectToken, cfg.subjectTokenType, actorToken, cfg.actorTokenType, cfg)
}

// Delegate performs a token exchange with delegation semantics.
//
// In ZITADEL, delegation and impersonation are functionally equivalent.
// Both result in a token with an `act` claim that identifies the actor.
// This function is provided as an alias for clarity in code that specifically
// implements delegation patterns.
//
// See [Impersonate] for detailed documentation.
func Delegate(
	ctx context.Context,
	z *zitadel.Zitadel,
	subjectToken string,
	actorToken string,
	opts ...Option,
) (*Result, error) {
	return Impersonate(ctx, z, subjectToken, actorToken, opts...)
}

// Exchange performs a simple token exchange without impersonation.
//
// Use this to:
//   - Reduce the scope of a token
//   - Reduce the audience of a token
//   - Convert an opaque token to a JWT (or vice versa)
//
// Example - reduce scope:
//
//	result, err := tokenexchange.Exchange(ctx,
//	    z,
//	    myAccessToken,
//	    tokenexchange.SubjectIsAccessToken(),
//	    tokenexchange.WithScopes("openid"),
//	)
//
// Example - convert to JWT:
//
//	result, err := tokenexchange.Exchange(ctx,
//	    z,
//	    opaqueToken,
//	    tokenexchange.SubjectIsAccessToken(),
//	    tokenexchange.WithRequestedTokenType(oidc.JWTTokenType),
//	)
func Exchange(
	ctx context.Context,
	z *zitadel.Zitadel,
	subjectToken string,
	opts ...Option,
) (*Result, error) {
	if subjectToken == "" {
		return nil, errors.New("tokenexchange: subject token is required")
	}

	cfg := &config{
		subjectTokenType: oidc.AccessTokenType,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return doExchange(ctx, z, subjectToken, cfg.subjectTokenType, "", "", cfg)
}

func doExchange(
	ctx context.Context,
	z *zitadel.Zitadel,
	subjectToken string,
	subjectTokenType oidc.TokenType,
	actorToken string,
	actorTokenType oidc.TokenType,
	cfg *config,
) (*Result, error) {
	te, err := tokenexchange.NewTokenExchanger(
		ctx,
		z.Origin(),
		tokenexchange.WithHTTPClient(http.NewClient(z)),
	)
	if err != nil {
		return nil, err
	}

	resp, err := tokenexchange.ExchangeToken(
		ctx,
		te,
		subjectToken,
		subjectTokenType,
		actorToken,
		actorTokenType,
		nil,
		cfg.audience,
		cfg.scopes,
		cfg.requestedTokenType,
	)
	if err != nil {
		return nil, err
	}

	return &Result{
		AccessToken:  resp.AccessToken,
		TokenType:    resp.TokenType,
		IDToken:      resp.IDToken,
		RefreshToken: resp.RefreshToken,
		ExpiresIn:    int(resp.ExpiresIn),
		Scopes:       resp.Scopes,
	}, nil
}
