package oidc

import (
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v2/pkg/authentication"
)

var _ authentication.Ctx = (*UserInfoContext)(nil)

// UserInfoContext implements the [authentication.Ctx] interface with the [oidc.UserInfo] as underlying data.
type UserInfoContext struct {
	*oidc.UserInfo
	*oidc.IDTokenClaims
}

// IsAuthenticated implements [authentication.Ctx] by checking the `sub` claim of the [oidc.UserInfo].
func (c *UserInfoContext) IsAuthenticated() bool {
	if c == nil {
		return false
	}
	return c.UserInfo.Subject != ""
}
