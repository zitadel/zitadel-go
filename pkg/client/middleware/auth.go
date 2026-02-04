package middleware

import (
	"context"
	"errors"
	"net/http"
	"os"

	"github.com/zitadel/oidc/v3/pkg/client/profile"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
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
type JWTDirectTokenSource func() (oauth2.TokenSource, error)

func JWTProfileFromPath(ctx context.Context, keyPath string) JWTProfileTokenSource {
	return JWTProfileFromPathWithHTTPClient(ctx, keyPath, nil)
}

// JWTProfileFromPathWithHTTPClient creates a JWTProfileTokenSource from the key file at the provided path.
// The httpClient is used for OIDC discovery and token requests. You can customize it to set timeouts,
// TLS settings (e.g., custom CA), proxies, etc. If nil, the default HTTP client is used.
func JWTProfileFromPathWithHTTPClient(ctx context.Context, keyPath string, httpClient *http.Client) JWTProfileTokenSource {
	return func(issuer string, scopes []string) (oauth2.TokenSource, error) {
		keyData, err := client.ConfigFromKeyFile(keyPath)
		if err != nil {
			return nil, err
		}
		return JWTProfileFromKeyAndUserIDWithHTTPClient(ctx, keyData.Key, keyData.KeyID, keyData.UserID, httpClient)(issuer, scopes)
	}
}

func JWTProfileFromFileData(ctx context.Context, fileData []byte) JWTProfileTokenSource {
	return JWTProfileFromFileDataWithHTTPClient(ctx, fileData, nil)
}

// JWTProfileFromFileDataWithHTTPClient creates a JWTProfileTokenSource from the provided key file data.
// The httpClient is used for OIDC discovery and token requests. You can customize it to set timeouts,
// TLS settings (e.g., custom CA), proxies, etc. If nil, the default HTTP client is used.
func JWTProfileFromFileDataWithHTTPClient(ctx context.Context, fileData []byte, httpClient *http.Client) JWTProfileTokenSource {
	return func(issuer string, scopes []string) (oauth2.TokenSource, error) {
		keyData, err := client.ConfigFromKeyFileData(fileData)
		if err != nil {
			return nil, err
		}
		return JWTProfileFromKeyAndUserIDWithHTTPClient(ctx, keyData.Key, keyData.KeyID, keyData.UserID, httpClient)(issuer, scopes)
	}
}

func JWTProfileFromKeyAndUserID(ctx context.Context, key []byte, keyID, userID string) JWTProfileTokenSource {
	return JWTProfileFromKeyAndUserIDWithHTTPClient(ctx, key, keyID, userID, nil)
}

// JWTProfileFromKeyAndUserIDWithHTTPClient creates a JWTProfileTokenSource from the provided key, key ID, and user ID.
// The httpClient is used for OIDC discovery and token requests. You can customize it to set timeouts,
// TLS settings (e.g., custom CA), proxies, etc. If nil, the default HTTP client is used.
func JWTProfileFromKeyAndUserIDWithHTTPClient(ctx context.Context, key []byte, keyID, userID string, httpClient *http.Client) JWTProfileTokenSource {
	return func(issuer string, scopes []string) (oauth2.TokenSource, error) {
		if httpClient != nil {
			return profile.NewJWTProfileTokenSource(ctx, issuer, userID, keyID, key, scopes, profile.WithHTTPClient(httpClient))
		}
		return profile.NewJWTProfileTokenSource(ctx, issuer, userID, keyID, key, scopes)
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
