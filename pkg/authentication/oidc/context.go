package oidc

import (
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/authentication"
)

var _ authentication.Ctx = (*UserInfoContext)(nil)

// UserInfoContext implements the [authentication.Ctx] interface with the [oidc.UserInfo] as underlying data.
type UserInfoContext[C oidc.IDClaims, S rp.SubjectGetter] struct {
	UserInfo S
	Tokens   *oidc.Tokens[C]
}

// IsAuthenticated implements [authentication.Ctx] by checking the `sub` claim of the [oidc.UserInfo].
func (c *UserInfoContext[C, S]) IsAuthenticated() bool {
	if c == nil {
		return false
	}
	return c.UserInfo.GetSubject() != ""
}

func (c *UserInfoContext[C, S]) SetTokens(tokens *oidc.Tokens[C]) {
	c.Tokens = tokens
}
func (c *UserInfoContext[C, S]) GetTokens() *oidc.Tokens[C] {
	return c.Tokens
}
func (c *UserInfoContext[C, S]) SetUserInfo(info S) {
	c.UserInfo = info
}
func (c *UserInfoContext[C, S]) GetUserInfo() S {
	return c.UserInfo
}
