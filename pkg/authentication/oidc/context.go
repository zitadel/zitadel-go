package oidc

import (
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// UserInfoContext implements the [authentication.Ctx], resp. [Ctx] interface with the [oidc.UserInfo] as underlying data.
type UserInfoContext[C oidc.IDClaims, S rp.SubjectGetter] struct {
	UserInfo S
	Tokens   *oidc.Tokens[C]
}

func (c *UserInfoContext[C, S]) New() Ctx[C, S] {
	return &UserInfoContext[C, S]{}
}

// IsAuthenticated implements [authentication.Ctx] by checking the `sub` claim of the [oidc.UserInfo].
func (c *UserInfoContext[C, S]) IsAuthenticated() bool {
	if c == nil {
		return false
	}
	return c.UserInfo.GetSubject() != ""
}

// SetTokens implements [Ctx]
func (c *UserInfoContext[C, S]) SetTokens(tokens *oidc.Tokens[C]) {
	c.Tokens = tokens
}

// GetTokens implements [Ctx]
func (c *UserInfoContext[C, S]) GetTokens() *oidc.Tokens[C] {
	return c.Tokens
}

// SetUserInfo implements [Ctx]
func (c *UserInfoContext[C, S]) SetUserInfo(info S) {
	c.UserInfo = info
}

// GetUserInfo implements [Ctx]
func (c *UserInfoContext[C, S]) GetUserInfo() S {
	return c.UserInfo
}
