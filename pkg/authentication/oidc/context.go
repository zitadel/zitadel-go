package oidc

import (
	"reflect"
	"time"

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

// IsAuthenticated implements [authentication.Ctx] by checking the `sub` claim of the [oidc.UserInfo]
// and the `exp` claim of the [oidc.Tokens] ID token.
func (c *UserInfoContext[C, S]) IsAuthenticated() bool {
	if c == nil {
		return false
	}
	if c.Tokens != nil && !isNilClaims(c.Tokens.IDTokenClaims) {
		if expiration := c.Tokens.IDTokenClaims.GetExpiration(); !expiration.IsZero() && !time.Now().Before(expiration) {
			return false
		}
	}
	return c.UserInfo.GetSubject() != ""
}

// isNilClaims reports whether claims is a nil pointer/interface. It's needed because
// claims is a generic type parameter, so a plain `claims == nil` comparison doesn't
// compile and comparing the boxed `any(claims) != nil` doesn't catch a typed nil pointer.
func isNilClaims[C oidc.IDClaims](claims C) bool {
	v := reflect.ValueOf(claims)
	if !v.IsValid() {
		// claims is a nil interface value (e.g. C is instantiated as the
		// oidc.IDClaims interface itself rather than a concrete pointer type).
		return true
	}
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
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

// GetExpiration returns the expiration time of the ID token, or zero time if not set.
func (c *UserInfoContext[C, S]) GetExpiration() time.Time {
	if c == nil || c.Tokens == nil || isNilClaims(c.Tokens.IDTokenClaims) {
		return time.Time{}
	}
	return c.Tokens.IDTokenClaims.GetExpiration()
}
