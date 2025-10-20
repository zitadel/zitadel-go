package authorization

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthorizer_CheckAuthorization(t *testing.T) {
	type args struct {
		ctx     context.Context
		token   string
		options []CheckOption
	}
	type testCase[T Ctx] struct {
		name        string
		a           Authorizer[T]
		args        args
		wantAuthCtx T
		wantErr     error
	}
	tests := []testCase[*testCtx]{
		{
			name: "empty token, unauthorized error",
			a: Authorizer[*testCtx]{
				verifier: &testVerifier[*testCtx]{},
				logger:   slog.Default(),
			},
			args: args{
				ctx:     context.Background(),
				token:   "",
				options: nil,
			},
			wantAuthCtx: nil,
			wantErr:     NewErrorUnauthorized(ErrMissingToken),
		},
		{
			name: "malformed token, unauthorized error",
			a: Authorizer[*testCtx]{
				verifier: &testVerifier[*testCtx]{},
				logger:   slog.Default(),
			},
			args: args{
				ctx:     context.Background(),
				token:   "token",
				options: nil,
			},
			wantAuthCtx: nil,
			wantErr:     NewErrorUnauthorized(ErrMissingToken),
		},
		{
			name: "missing role, permissiondenied error",
			a: Authorizer[*testCtx]{
				verifier: &testVerifier[*testCtx]{
					ctx: &testCtx{
						isAuthorized: true,
					},
				},
				logger: slog.Default(),
			},
			args: args{
				ctx:     context.Background(),
				token:   "Bearer token",
				options: []CheckOption{WithRole("test")},
			},
			wantAuthCtx: nil,
			wantErr:     NewErrorPermissionDenied(ErrMissingRole),
		},
		{
			name: "authorized",
			a: Authorizer[*testCtx]{
				verifier: &testVerifier[*testCtx]{
					ctx: &testCtx{
						isAuthorized: true,
					},
				},
				logger: slog.Default(),
			},
			args: args{
				ctx:     context.Background(),
				token:   "Bearer token",
				options: nil,
			},
			wantAuthCtx: &testCtx{isAuthorized: true, token: "Bearer token"},
			wantErr:     nil,
		},
		{
			name: "authorized with role",
			a: Authorizer[*testCtx]{
				verifier: &testVerifier[*testCtx]{
					ctx: &testCtx{
						isAuthorized:  true,
						isGrantedRole: true,
					},
				},
				logger: slog.Default(),
			},
			args: args{
				ctx:     context.Background(),
				token:   "Bearer token",
				options: []CheckOption{WithRole("test")},
			},
			wantAuthCtx: &testCtx{isAuthorized: true, isGrantedRole: true, token: "Bearer token"},
			wantErr:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAuthCtx, err := tt.a.CheckAuthorization(tt.args.ctx, tt.args.token, tt.args.options...)
			assert.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, gotAuthCtx, tt.wantAuthCtx)
		})
	}
}

type testVerifier[T Ctx] struct {
	ctx T
	err error
}

func (t *testVerifier[T]) CheckAuthorization(_ context.Context, _ string) (T, error) {
	return t.ctx, t.err
}

type testCtx struct {
	isAuthorized                bool
	organizationID              string
	userID                      string
	isGrantedRole               bool
	isGrantedRoleInOrganization bool
	token                       string
}

func (t *testCtx) SetToken(token string) {
	t.token = token
}

func (t *testCtx) GetToken() string {
	return t.token
}

func (t *testCtx) IsAuthorized() bool {
	if t == nil {
		return false
	}
	return t.isAuthorized
}

func (t *testCtx) OrganizationID() string {
	if t == nil {
		return ""
	}
	return t.organizationID
}

func (t *testCtx) UserID() string {
	if t == nil {
		return ""
	}
	return t.userID
}

func (t *testCtx) IsGrantedRole(_ string) bool {
	if t == nil {
		return false
	}
	return t.isGrantedRole
}

func (t *testCtx) IsGrantedRoleInOrganization(_, _ string) bool {
	if t == nil {
		return false
	}
	return t.isGrantedRoleInOrganization
}

func TestCheckForEmptyorMalformedToken(t *testing.T) {
	tests := []struct {
		name        string
		tokenHeader string
		wantErr     error
	}{
		{
			name:        "empty token header",
			tokenHeader: "",
			wantErr:     ErrMissingToken,
		},
		{
			name:        "whitespace only token header",
			tokenHeader: "   ",
			wantErr:     ErrMissingToken,
		},
		{
			name:        "token header without Bearer prefix",
			tokenHeader: "invalid-token",
			wantErr:     ErrMissingToken,
		},
		{
			name:        "token header with Bearer but no space",
			tokenHeader: "Bearertoken",
			wantErr:     ErrMissingToken,
		},
		{
			name:        "token header with Bearer prefix but empty token",
			tokenHeader: "Bearer ",
			wantErr:     ErrMissingToken,
		},
		{
			name:        "token header with Bearer prefix but only whitespace token",
			tokenHeader: "Bearer   ",
			wantErr:     ErrMissingToken,
		},
		{
			name:        "token header with Bearer prefix but tab and newline token",
			tokenHeader: "Bearer \t\n",
			wantErr:     ErrMissingToken,
		},
		{
			name:        "valid token with Bearer prefix",
			tokenHeader: "Bearer valid-token",
			wantErr:     nil,
		},
		{
			name:        "valid token with Bearer prefix and extra whitespace",
			tokenHeader: "  Bearer valid-token  ",
			wantErr:     nil,
		},
		{
			name:        "valid token with Bearer prefix and leading whitespace",
			tokenHeader: " Bearer valid-token",
			wantErr:     nil,
		},
		{
			name:        "valid token with Bearer prefix and trailing whitespace",
			tokenHeader: "Bearer valid-token ",
			wantErr:     nil,
		},
		{
			name:        "valid token with Bearer prefix and multiple spaces",
			tokenHeader: "Bearer  valid-token",
			wantErr:     nil,
		},
		{
			name:        "token header with lowercase bearer prefix",
			tokenHeader: "bearer valid-token",
			wantErr:     ErrMissingToken,
		},
		{
			name:        "token header with mixed case bearer prefix",
			tokenHeader: "BeArEr valid-token",
			wantErr:     ErrMissingToken,
		},
		{
			name:        "token header with Bearer prefix and special characters",
			tokenHeader: "Bearer token-with-special-chars!@#$%",
			wantErr:     nil,
		},
		{
			name:        "token header with Bearer prefix and JWT token",
			tokenHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			wantErr:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkForEmptyorMalformedToken(tt.tokenHeader)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
