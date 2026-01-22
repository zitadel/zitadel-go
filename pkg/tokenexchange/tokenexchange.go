package tokenexchange

import (
	"context"
	"errors"

	"github.com/zitadel/oidc/v3/pkg/client/tokenexchange"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	httputil "github.com/zitadel/zitadel-go/v3/pkg/tokenexchange/internal/http"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

// Result contains the tokens returned from a token exchange.
type Result struct {
	AccessToken  string
	TokenType    string
	IDToken      string
	RefreshToken string
	ExpiresIn    int
	Scopes       []string
}

// Impersonate performs a token exchange to act as another user.
//
// Client authentication is required. Use [WithClientAuth] with either
// [ClientCredentials] or [JWTProfile].
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

	if cfg.clientAuth == nil {
		return nil, errors.New("tokenexchange: client authentication is required; use WithClientAuth")
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
// Client authentication is required. Use [WithClientAuth] with either
// [ClientCredentials] or [JWTProfile].
//
// Use this to:
//   - Reduce the scope of a token
//   - Reduce the audience of a token
//   - Convert an opaque token to a JWT (or vice versa)
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

	if cfg.clientAuth == nil {
		return nil, errors.New("tokenexchange: client authentication is required; use WithClientAuth")
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
	httpClient := httputil.NewClient(z)

	exchanger, err := cfg.clientAuth.createExchanger(ctx, z.Origin(), httpClient)
	if err != nil {
		return nil, err
	}

	resp, err := tokenexchange.ExchangeToken(
		ctx,
		exchanger,
		subjectToken,
		subjectTokenType,
		actorToken,
		actorTokenType,
		cfg.resource,
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
