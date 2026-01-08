package zitadel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"github.com/zitadel/zitadel-go/v3/pkg/client/middleware"
)

type Connection struct {
	issuer                string
	api                   string
	jwtProfileTokenSource middleware.JWTProfileTokenSource
	jwtDirectTokenSource  middleware.JWTDirectTokenSource
	tokenSource           oauth2.TokenSource
	scopes                []string
	orgID                 string
	insecure              bool
	insecureSkipVerify    bool
	transportHeaders      map[string]string
	unaryInterceptors     []grpc.UnaryClientInterceptor
	streamInterceptors    []grpc.StreamClientInterceptor
	dialOptions           []grpc.DialOption
	*grpc.ClientConn
}

func NewConnection(ctx context.Context, issuer, api string, scopes []string, options ...Option) (*Connection, error) {
	c := &Connection{
		issuer:                issuer,
		api:                   api,
		jwtProfileTokenSource: middleware.JWTProfileFromPath(ctx, middleware.OSKeyPath()),
		scopes:                scopes,
		transportHeaders:      make(map[string]string),
	}

	for _, option := range options {
		if err := option(c); err != nil {
			return nil, err
		}
	}

	err := c.setInterceptors(c.issuer, c.orgID, c.scopes, c.jwtProfileTokenSource)
	if err != nil {
		return nil, err
	}
	if len(c.transportHeaders) > 0 {
		headerUnary := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			for k, v := range c.transportHeaders {
				ctx = metadata.AppendToOutgoingContext(ctx, k, v)
			}
			return invoker(ctx, method, req, reply, cc, opts...)
		}
		headerStream := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			for k, v := range c.transportHeaders {
				ctx = metadata.AppendToOutgoingContext(ctx, k, v)
			}
			return streamer(ctx, desc, cc, method, opts...)
		}
		c.unaryInterceptors = append(c.unaryInterceptors, headerUnary)
		c.streamInterceptors = append(c.streamInterceptors, headerStream)
	}

	dialOptions := []grpc.DialOption{
		grpc.WithChainUnaryInterceptor(
			c.unaryInterceptors...,
		),
		grpc.WithChainStreamInterceptor(
			c.streamInterceptors...,
		),
	}
	dialOptions = append(dialOptions, c.dialOptions...)
	opt, err := transportOption(c.api, c.insecure, c.insecureSkipVerify)
	if err != nil {
		return nil, err
	}
	dialOptions = append(dialOptions, opt)
	//nolint:staticcheck // grpc.Dial is retained for compatibility with existing usage.
	conn, err := grpc.Dial(c.api, dialOptions...)
	if err != nil {
		return nil, err
	}
	c.ClientConn = conn

	return c, nil
}

func (c *Connection) setInterceptors(issuer, orgID string, scopes []string, jwtProfileTokenSource middleware.JWTProfileTokenSource) error {
	var auth *middleware.AuthInterceptor
	var err error
	if c.tokenSource != nil {
		auth, err = middleware.NewGenericAuthenticator(c.tokenSource)
	} else if c.jwtDirectTokenSource != nil {
		auth, err = middleware.NewPresignedJWTAuthenticator(c.jwtDirectTokenSource)
	} else {
		auth, err = middleware.NewAuthenticator(c.issuer, c.jwtProfileTokenSource, c.scopes...)
	}
	if err != nil {
		return err
	}

	c.unaryInterceptors = append(c.unaryInterceptors, auth.Unary())
	c.streamInterceptors = append(c.streamInterceptors, auth.Stream())
	if orgID != "" {
		org := middleware.NewOrgInterceptor(orgID)
		c.unaryInterceptors = append(c.unaryInterceptors, org.Unary())
		c.streamInterceptors = append(c.streamInterceptors, org.Stream())
	}
	return nil
}

func transportOption(api string, insecure bool, insecureSkipVerify bool) (grpc.DialOption, error) {
	if insecure {
		//nolint:staticcheck // WithInsecure is used for compatibility; callers control security.
		return grpc.WithInsecure(), nil
	}
	certs, err := transportCredentials(api, insecureSkipVerify)
	if err != nil {
		return nil, err
	}
	return grpc.WithTransportCredentials(certs), nil
}

func transportCredentials(api string, insecureSkipVerify bool) (credentials.TransportCredentials, error) {
	ca, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if ca == nil {
		ca = x509.NewCertPool()
	}

	servernameWithoutPort := strings.Split(api, ":")[0]
	tlsConfig := &tls.Config{
		RootCAs:            ca,
		InsecureSkipVerify: insecureSkipVerify,
		ServerName:         servernameWithoutPort,
	}
	return credentials.NewTLS(tlsConfig), nil
}

type Option func(*Connection) error

// WithCustomURL replaces the standard issuer (https://issuer.zitadel.ch) and api endpoint (api.zitadel.ch:443)
func WithCustomURL(issuer, api string) func(*Connection) error {
	return func(client *Connection) error {
		client.issuer = issuer
		client.api = api
		return nil
	}
}

// WithTokenSource sets a generic oauth2.TokenSource for authentication.
// This is the most flexible option and should be preferred.
// If set, it will be used over WithJWTProfileTokenSource or WithJWTDirectTokenSource.
func WithTokenSource(ts oauth2.TokenSource) Option {
	return func(c *Connection) error {
		c.tokenSource = ts
		return nil
	}
}

// WithJWTProfileTokenSource sets the provider used for the authentication
// if not set, the key file will be read from the path set in env var ZITADEL_KEY_PATH
func WithJWTProfileTokenSource(provider middleware.JWTProfileTokenSource) func(*Connection) error {
	return func(client *Connection) error {
		client.jwtProfileTokenSource = provider
		return nil
	}
}

// Use a pre-signed JWT for authentication
func WithJWTDirectTokenSource(jwt string) func(*Connection) error {
	return func(client *Connection) error {
		client.jwtDirectTokenSource = func() (oauth2.TokenSource, error) {
			return oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: jwt,
				TokenType:   oidc.BearerToken,
			}), nil
		}
		return nil
	}
}

// WithOrgID sets the organization context (where the api calls are executed)
// if not set the resource owner (organization) of the calling user will be used
func WithOrgID(orgID string) func(*Connection) error {
	return func(client *Connection) error {
		client.orgID = orgID
		return nil
	}
}

// WithInsecure disables transport security for the client connection
// use only when absolutely necessary (local development)
func WithInsecure() func(*Connection) error {
	return func(client *Connection) error {
		client.insecure = true
		return nil
	}
}

// WithInsecureSkipVerifyTLS skips certificate verification when using TLS.
// Use only for local development with self-signed certs.
func WithInsecureSkipVerifyTLS() func(*Connection) error {
	return func(client *Connection) error {
		client.insecureSkipVerify = true
		return nil
	}
}

// WithTransportHeader sets a custom header on outgoing gRPC requests.
func WithTransportHeader(key, value string) func(*Connection) error {
	return func(client *Connection) error {
		client.transportHeaders[key] = value
		return nil
	}
}

// WithUnaryInterceptors adds non ZITADEL specific interceptors to the connection
func WithUnaryInterceptors(interceptors ...grpc.UnaryClientInterceptor) func(*Connection) error {
	return func(client *Connection) error {
		client.unaryInterceptors = append(client.unaryInterceptors, interceptors...)
		return nil
	}
}

// WithStreamInterceptors adds non ZITADEL specific interceptors to the connection
func WithStreamInterceptors(interceptors ...grpc.StreamClientInterceptor) func(*Connection) error {
	return func(client *Connection) error {
		client.streamInterceptors = append(client.streamInterceptors, interceptors...)
		return nil
	}
}

// WithDialOptions adds non ZITADEL specific dial options to the connection
func WithDialOptions(opts ...grpc.DialOption) func(*Connection) error {
	return func(client *Connection) error {
		client.dialOptions = append(client.dialOptions, opts...)
		return nil
	}
}
