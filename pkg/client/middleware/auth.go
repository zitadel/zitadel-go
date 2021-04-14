package middleware

import (
	"context"
	"os"

	"github.com/caos/oidc/pkg/client/profile"
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

//NewAuthInterceptor creates an interceptor which authenticates a service account with JWT Profile using a key.json.
//There returned token will be used for authorization in all calls
//if expired, the token will be automatically refreshed
func NewAuthInterceptor(issuer, keyPath string, scopes ...string) (*AuthInterceptor, error) {
	ts, err := profile.NewJWTProfileTokenSourceFromKeyFile(issuer, keyPath, scopes)
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
