package oidc_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"

	zitadeloidc "github.com/zitadel/zitadel-go/v3/pkg/authentication/oidc"
)

type testContext = *zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]

func TestUserInfoContext_IsAuthenticated(t *testing.T) {
	tests := []struct {
		name string
		ctx  testContext
		want bool
	}{
		{
			name: "nil context",
			ctx:  nil,
			want: false,
		},
		{
			name: "no subject",
			ctx: &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
				UserInfo: &oidc.UserInfo{},
			},
			want: false,
		},
		{
			name: "subject without tokens",
			ctx: &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
				UserInfo: &oidc.UserInfo{Subject: "user-1"},
			},
			want: true,
		},
		{
			name: "tokens without id token claims",
			ctx: &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
				UserInfo: &oidc.UserInfo{Subject: "user-1"},
				Tokens:   &oidc.Tokens[*oidc.IDTokenClaims]{IDToken: "id-token"},
			},
			want: true,
		},
		{
			name: "id token without expiration",
			ctx: &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
				UserInfo: &oidc.UserInfo{Subject: "user-1"},
				Tokens: &oidc.Tokens[*oidc.IDTokenClaims]{
					IDTokenClaims: &oidc.IDTokenClaims{},
				},
			},
			want: true,
		},
		{
			name: "id token not yet expired",
			ctx: &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
				UserInfo: &oidc.UserInfo{Subject: "user-1"},
				Tokens: &oidc.Tokens[*oidc.IDTokenClaims]{
					IDTokenClaims: &oidc.IDTokenClaims{
						TokenClaims: oidc.TokenClaims{
							Expiration: oidc.FromTime(time.Now().Add(time.Hour)),
						},
					},
				},
			},
			want: true,
		},
		{
			name: "id token expired",
			ctx: &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
				UserInfo: &oidc.UserInfo{Subject: "user-1"},
				Tokens: &oidc.Tokens[*oidc.IDTokenClaims]{
					IDTokenClaims: &oidc.IDTokenClaims{
						TokenClaims: oidc.TokenClaims{
							Expiration: oidc.FromTime(time.Now().Add(-time.Hour)),
						},
					},
				},
			},
			want: false,
		},
		{
			// The access token's expiry must not affect session validity: only the ID
			// token's exp claim does. An expired access token is routinely refreshed
			// in the background without invalidating the underlying identity assertion.
			name: "access token expired but id token still valid",
			ctx: &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
				UserInfo: &oidc.UserInfo{Subject: "user-1"},
				Tokens: &oidc.Tokens[*oidc.IDTokenClaims]{
					Token: &oauth2.Token{Expiry: time.Now().Add(-time.Hour)},
					IDTokenClaims: &oidc.IDTokenClaims{
						TokenClaims: oidc.TokenClaims{
							Expiration: oidc.FromTime(time.Now().Add(time.Hour)),
						},
					},
				},
			},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.ctx.IsAuthenticated())
		})
	}
}

// TestUserInfoContext_IsAuthenticated_NilInterfaceClaims covers instantiating C as the
// bare oidc.IDClaims interface rather than a concrete pointer type. In that case a zero
// value IDTokenClaims is a nil interface, not a nil pointer, which reflect.ValueOf reports
// as an invalid Value rather than a nil Ptr/Interface Value.
func TestUserInfoContext_IsAuthenticated_NilInterfaceClaims(t *testing.T) {
	ctx := &zitadeloidc.UserInfoContext[oidc.IDClaims, *oidc.UserInfo]{
		UserInfo: &oidc.UserInfo{Subject: "user-1"},
		Tokens:   &oidc.Tokens[oidc.IDClaims]{IDToken: "id-token"},
	}
	assert.True(t, ctx.IsAuthenticated())
}

func TestUserInfoContext_GetExpiration(t *testing.T) {
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	tests := []struct {
		name string
		ctx  testContext
		want time.Time
	}{
		{
			name: "nil context",
			ctx:  nil,
			want: time.Time{},
		},
		{
			name: "nil tokens",
			ctx: &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
				UserInfo: &oidc.UserInfo{Subject: "user-1"},
				Tokens:   nil,
			},
			want: time.Time{},
		},
		{
			name: "tokens with nil IDTokenClaims",
			ctx: &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
				UserInfo: &oidc.UserInfo{Subject: "user-1"},
				Tokens:   &oidc.Tokens[*oidc.IDTokenClaims]{IDToken: "token"},
			},
			want: time.Time{},
		},
		{
			name: "valid expiration",
			ctx: &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
				UserInfo: &oidc.UserInfo{Subject: "user-1"},
				Tokens: &oidc.Tokens[*oidc.IDTokenClaims]{
					IDTokenClaims: &oidc.IDTokenClaims{
						TokenClaims: oidc.TokenClaims{
							Expiration: oidc.FromTime(exp),
						},
					},
				},
			},
			want: exp,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.ctx.GetExpiration()
			if tc.want.IsZero() {
				assert.True(t, got.IsZero())
			} else {
				assert.WithinDuration(t, tc.want, got, time.Second)
			}
		})
	}
}

func TestUserInfoContext_GetExpiration_NilInterfaceClaims(t *testing.T) {
	ctx := &zitadeloidc.UserInfoContext[oidc.IDClaims, *oidc.UserInfo]{
		UserInfo: &oidc.UserInfo{Subject: "user-1"},
		Tokens:   &oidc.Tokens[oidc.IDClaims]{IDToken: "id-token"},
	}
	assert.True(t, ctx.GetExpiration().IsZero())
}

