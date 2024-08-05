package system

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/client/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/system"
)

type Client struct {
	Connection *zitadel.Connection
	system.SystemServiceClient
}

func NewClient(ctx context.Context, issuer, api string, source JWTAuthenticationSource, opts ...Option) (*Client, error) {
	options := make([]zitadel.Option, len(opts)+1)
	options[0] = zitadel.WithJWTProfileTokenSource(source())
	for i, opt := range opts {
		options[i+1] = opt()
	}
	conn, err := zitadel.NewConnection(ctx, issuer, api, nil, options...)
	if err != nil {
		return nil, err
	}
	return &Client{
		Connection:          conn,
		SystemServiceClient: system.NewSystemServiceClient(conn.ClientConn),
	}, nil
}

type Option func() zitadel.Option

// WithInsecure disables transport security for the client connection
// use only when absolutely necessary (e.g. local development)
func WithInsecure() func() zitadel.Option {
	return func() zitadel.Option {
		return zitadel.WithInsecure()
	}
}

type JWTAuthenticationSource func() middleware.JWTProfileTokenSource

// JWTProfileFromPath reads the key at the provided path and creates a JWTAuthenticationSource (oauth2.TokensSource)
// to authenticate against the SystemAPI
func JWTProfileFromPath(keyPath, userID string) JWTAuthenticationSource {
	return func() middleware.JWTProfileTokenSource {
		return func(issuer string, _ []string) (oauth2.TokenSource, error) {
			key, err := os.ReadFile(keyPath)
			if err != nil {
				return nil, err
			}
			return jwtAuthenticationTokenSource(issuer, userID, key)
		}
	}
}

// JWTProfileFromKey creates a JWTAuthenticationSource (oauth2.TokensSource) from the provided key (and userID)
// to authenticate against the SystemAPI
func JWTProfileFromKey(key []byte, userID string) JWTAuthenticationSource {
	return func() middleware.JWTProfileTokenSource {
		return func(issuer string, _ []string) (oauth2.TokenSource, error) {
			return jwtAuthenticationTokenSource(issuer, userID, key)
		}
	}
}

type jwtAuthentication struct {
	userID     string
	audience   []string
	signer     jose.Signer
	httpClient *http.Client
}

func jwtAuthenticationTokenSource(issuer, userID string, key []byte) (oauth2.TokenSource, error) {
	signer, err := client.NewSignerFromPrivateKeyByte(key, "")
	if err != nil {
		return nil, err
	}
	source := &jwtAuthentication{
		userID:     userID,
		audience:   []string{issuer},
		signer:     signer,
		httpClient: http.DefaultClient,
	}
	return source, nil
}

func (j *jwtAuthentication) Token() (*oauth2.Token, error) {
	token, err := client.SignedJWTProfileAssertion(j.userID, j.audience, time.Hour, j.signer)
	if err != nil {
		return nil, err
	}
	return &oauth2.Token{
		AccessToken: token,
		TokenType:   oidc.BearerToken,
		Expiry:      time.Now().Add(time.Hour - 5*time.Second),
	}, nil
}
