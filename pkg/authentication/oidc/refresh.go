package oidc

import (
	"context"
	"errors"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

var (
	ErrRefreshDisabled = errors.New("refresh is not enabled")
	ErrNoRefreshToken  = errors.New("session has no refresh token")
)

// Refresh renews authCtx with the refresh token grant. It is called by
// [authentication.Authenticator.Refresh].
// The response must include an ID token, since its exp claim is the session's
// expiration; a response without one fails with [rp.ErrMissingIDToken].
// The user info is carried over from authCtx unchanged.
func (c *codeFlowAuthentication[T, C, S]) Refresh(ctx context.Context, authCtx T) (T, error) {
	var t T
	if !c.refresh {
		return t, ErrRefreshDisabled
	}
	tokens := authCtx.GetTokens()
	if tokens == nil || tokens.Token == nil || tokens.RefreshToken == "" {
		return t, ErrNoRefreshToken
	}
	refreshed, err := rp.RefreshTokens[C](ctx, c.relyingParty, tokens.RefreshToken, "", "")
	if err != nil {
		return t, err
	}
	if refreshed.IDToken == "" {
		return t, rp.ErrMissingIDToken
	}
	// The IdP may keep the refresh token rather than rotating it, in which case
	// the response omits it.
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = tokens.RefreshToken
	}
	renewed := authCtx.New().(T)
	renewed.SetTokens(refreshed)
	renewed.SetUserInfo(authCtx.GetUserInfo())
	return renewed, nil
}
