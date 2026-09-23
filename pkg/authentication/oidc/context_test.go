package oidc_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zitadel/oidc/v3/pkg/oidc"

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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.ctx.IsAuthenticated())
		})
	}
}
