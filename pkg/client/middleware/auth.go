package middleware

import (
	"context"
	"errors"
	"os"

	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/internal/httpclient"
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

// JWTProfileTokenSourceContext is like [JWTProfileTokenSource], but receives the context of the
// connection being created. That context carries the HTTP client (see [oauth2.HTTPClient]) configured
// through the connection's TLS and transport header options, which the token source should use for
// the OIDC discovery and token requests. The helpers in this package do so.
type JWTProfileTokenSourceContext func(ctx context.Context, issuer string, scopes []string) (oauth2.TokenSource, error)
type JWTDirectTokenSource func() (oauth2.TokenSource, error)

// JWTProfileFromPath creates a JWTProfileTokenSource. If the ctx carries an HTTP client (see [oauth2.HTTPClient]),
// it is used for the OIDC discovery and token requests. Use [JWTProfileFromPathContext] to have the connection's
// TLS and transport header options applied.
func JWTProfileFromPath(ctx context.Context, keyPath string) JWTProfileTokenSource {
	return func(issuer string, scopes []string) (oauth2.TokenSource, error) {
		keyData, err := client.ConfigFromKeyFile(keyPath)
		if err != nil {
			return nil, err
		}
		return JWTProfileFromKeyAndUserID(ctx, keyData.Key, keyData.KeyID, keyData.UserID)(issuer, scopes)
	}
}

// JWTProfileFromFileData creates a JWTProfileTokenSource. If the ctx carries an HTTP client (see [oauth2.HTTPClient]),
// it is used for the OIDC discovery and token requests. Use [JWTProfileFromFileDataContext] to have the connection's
// TLS and transport header options applied.
func JWTProfileFromFileData(ctx context.Context, fileData []byte) JWTProfileTokenSource {
	return func(issuer string, scopes []string) (oauth2.TokenSource, error) {
		keyData, err := client.ConfigFromKeyFileData(fileData)
		if err != nil {
			return nil, err
		}
		return JWTProfileFromKeyAndUserID(ctx, keyData.Key, keyData.KeyID, keyData.UserID)(issuer, scopes)
	}
}

// JWTProfileFromKeyAndUserID creates a JWTProfileTokenSource. If the ctx carries an HTTP client (see [oauth2.HTTPClient]),
// it is used for the OIDC discovery and token requests. Use [JWTProfileFromKeyAndUserIDContext] to have the connection's
// TLS and transport header options applied.
func JWTProfileFromKeyAndUserID(ctx context.Context, key []byte, keyID, userID string) JWTProfileTokenSource {
	return func(issuer string, scopes []string) (oauth2.TokenSource, error) {
		return httpclient.JWTProfileTokenSource(ctx, issuer, userID, keyID, key, scopes)
	}
}

// JWTProfileFromPathContext is like [JWTProfileFromPath], but uses the context passed when the
// token source is created, so the connection's HTTP client applies to the discovery and token requests.
func JWTProfileFromPathContext(keyPath string) JWTProfileTokenSourceContext {
	return func(ctx context.Context, issuer string, scopes []string) (oauth2.TokenSource, error) {
		keyData, err := client.ConfigFromKeyFile(keyPath)
		if err != nil {
			return nil, err
		}
		return httpclient.JWTProfileTokenSource(ctx, issuer, keyData.UserID, keyData.KeyID, keyData.Key, scopes)
	}
}

// JWTProfileFromFileDataContext is like [JWTProfileFromFileData], but uses the context passed when the
// token source is created, so the connection's HTTP client applies to the discovery and token requests.
func JWTProfileFromFileDataContext(fileData []byte) JWTProfileTokenSourceContext {
	return func(ctx context.Context, issuer string, scopes []string) (oauth2.TokenSource, error) {
		keyData, err := client.ConfigFromKeyFileData(fileData)
		if err != nil {
			return nil, err
		}
		return httpclient.JWTProfileTokenSource(ctx, issuer, keyData.UserID, keyData.KeyID, keyData.Key, scopes)
	}
}

// JWTProfileFromKeyAndUserIDContext is like [JWTProfileFromKeyAndUserID], but uses the context passed when the
// token source is created, so the connection's HTTP client applies to the discovery and token requests.
func JWTProfileFromKeyAndUserIDContext(key []byte, keyID, userID string) JWTProfileTokenSourceContext {
	return func(ctx context.Context, issuer string, scopes []string) (oauth2.TokenSource, error) {
		return httpclient.JWTProfileTokenSource(ctx, issuer, userID, keyID, key, scopes)
	}
}

// NewGenericAuthenticator creates an interceptor from any provided oauth2.TokenSource.
// This is the most flexible constructor, allowing for use cases like Client
// Credentials, Personal Access Tokens, or other custom token sources.
func NewGenericAuthenticator(ts oauth2.TokenSource) (*AuthInterceptor, error) {
	if ts == nil {
		return nil, errors.New("token source cannot be nil")
	}
	return &AuthInterceptor{
		TokenSource: oauth2.ReuseTokenSource(nil, ts),
	}, nil
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

func NewPresignedJWTAuthenticator(jwtDirectTokenSource JWTDirectTokenSource) (*AuthInterceptor, error) {
	ts, err := jwtDirectTokenSource()
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
	token, err := interceptor.Token()
	if err != nil {
		return ctx, err
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", token.TokenType+" "+token.AccessToken), nil
}
