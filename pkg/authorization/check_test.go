package authorization

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slog"
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
			wantErr:     NewErrorUnauthorized(ErrEmptyAuthorizationHeader),
		},
		{
			name: "unauthorized, unauthorized error",
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
			wantErr:     NewErrorUnauthorized(nil),
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
				token:   "token",
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
				token:   "token",
				options: nil,
			},
			wantAuthCtx: &testCtx{isAuthorized: true},
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
				token:   "token",
				options: []CheckOption{WithRole("test")},
			},
			wantAuthCtx: &testCtx{isAuthorized: true, isGrantedRole: true},
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
	userID                      string
	isGrantedRole               bool
	isGrantedRoleInOrganization bool
}

func (t *testCtx) IsAuthorized() bool {
	if t == nil {
		return false
	}
	return t.isAuthorized
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
