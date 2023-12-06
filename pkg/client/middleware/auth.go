package middleware

import (
	"context"
	"os"

	"github.com/zitadel/oidc/v3/pkg/client/profile"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	ZitadelKeyPath = "ZITADEL_KEY_PATH"
)

func OSKeyPath() string {
	return os.Getenv(ZitadelKeyPath)
}

type AuthInterceptor struct {
	oauth2.TokenSource
}

type JWTProfileTokenSource func(issuer string, scopes []string) (oauth2.TokenSource, error)

func JWTProfileFromPath(ctx context.Context, keyPath string) JWTProfileTokenSource {
	return func(issuer string, scopes []string) (oauth2.TokenSource, error) {
		return profile.NewJWTProfileTokenSourceFromKeyFile(ctx, issuer, keyPath, scopes)
	}
}

func JWTProfileFromFileData(ctx context.Context, fileData []byte) JWTProfileTokenSource {
	return func(issuer string, scopes []string) (oauth2.TokenSource, error) {
		return profile.NewJWTProfileTokenSourceFromKeyFileData(ctx, issuer, fileData, scopes)
	}
}

func JWTProfileFromKeyAndUserID(ctx context.Context, key []byte, keyID, userID string) JWTProfileTokenSource {
	return func(issuer string, scopes []string) (oauth2.TokenSource, error) {
		return profile.NewJWTProfileTokenSource(ctx, issuer, userID, keyID, key, scopes)
	}
}

// NewAuthenticator creates an interceptor which authenticates a service account with a provided JWT Profile (using a key.json either as file or data).
// There returned token will be used for authorization in all calls
// if expired, the token will be automatically refreshed
func NewAuthenticator(issuer string, jwtProfileTokenSource JWTProfileTokenSource, scopes ...string) (*AuthInterceptor, error) {
	ts, err := jwtProfileTokenSource(issuer, scopes)
	if err != nil {
		return nil, err
	}
	return &AuthInterceptor{
		TokenSource: oauth2.ReuseTokenSource(nil, ts),
	}, nil
}

func (interceptor *AuthInterceptor) Unary() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		authCtx, err := interceptor.setToken(ctx)
		if err != nil {
			return err
		}
		return invoker(authCtx, method, req, reply, cc, opts...)
	}
}

func (interceptor *AuthInterceptor) Stream() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		authCtx, err := interceptor.setToken(ctx)
		if err != nil {
			return nil, err
		}
		return streamer(authCtx, desc, cc, method, opts...)
	}
}

func (interceptor *AuthInterceptor) setToken(ctx context.Context) (context.Context, error) {
	token, err := interceptor.TokenSource.Token()
	if err != nil {
		return ctx, err
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", token.TokenType+" "+token.AccessToken), nil
}
