package zitadel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/client/profile"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/middleware"
)

type Connection struct {
	issuer                string
	api                   string
	jwtProfileTokenSource middleware.JWTProfileTokenSource
	jwtDirectTokenSource  middleware.JWTDirectTokenSource
	tokenSource           oauth2.TokenSource
	httpClient            *http.Client
	scopes                []string
	orgID                 string
	insecure              bool
	insecureSkipVerify    bool
	caCertPool            *x509.CertPool
	transportHeaders      map[string]string
	unaryInterceptors     []grpc.UnaryClientInterceptor
	streamInterceptors    []grpc.StreamClientInterceptor
	dialOptions           []grpc.DialOption
	*grpc.ClientConn
}

func NewConnection(ctx context.Context, issuer, api string, scopes []string, options ...Option) (*Connection, error) {
	c := &Connection{
		issuer:           issuer,
		api:              api,
		scopes:           scopes,
		transportHeaders: make(map[string]string),
	}

	for _, option := range options {
		if err := option(c); err != nil {
			return nil, err
		}
	}

	// Only create a custom HTTP client if one wasn't already provided via WithHTTPClient
	if c.httpClient == nil && (c.insecureSkipVerify || c.caCertPool != nil || len(c.transportHeaders) > 0) {
		var baseTransport *http.Transport
		if t, ok := http.DefaultTransport.(*http.Transport); ok {
			baseTransport = t.Clone()
		} else {
			baseTransport = &http.Transport{
				Proxy: http.ProxyFromEnvironment,
			}
		}

		if c.insecureSkipVerify || c.caCertPool != nil {
			if baseTransport.TLSClientConfig == nil {
				baseTransport.TLSClientConfig = &tls.Config{}
			}
			if c.insecureSkipVerify {
				//nolint:gosec // InsecureSkipVerify is intentionally configurable for local development with self-signed certs.
				baseTransport.TLSClientConfig.InsecureSkipVerify = true
			}
			if c.caCertPool != nil {
				baseTransport.TLSClientConfig.RootCAs = c.caCertPool
			}
		}

		var rt http.RoundTripper = baseTransport
		if len(c.transportHeaders) > 0 {
			rt = &headerRoundTripper{
				rt:      baseTransport,
				headers: c.transportHeaders,
			}
		}

		c.httpClient = &http.Client{
			Transport: rt,
		}
	}

	if c.jwtProfileTokenSource == nil && c.jwtDirectTokenSource == nil && c.tokenSource == nil {
		c.jwtProfileTokenSource = createDefaultJWTProfileTokenSource(ctx, c.httpClient)
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
	opt, err := transportOption(c.api, c.insecure, c.insecureSkipVerify, c.caCertPool)
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
		// 1. We manually call the TokenSource generator.
		// Because you set this up in NewConnection, it ALREADY uses
		// the customHTTPClient that skips certificate checks.
		ts, err := c.jwtProfileTokenSourceWithHTTPClient(jwtProfileTokenSource)
		if err != nil {
			return err
		}

		// 2. We use the Generic Authenticator.
		// This DOES NOT perform its own failing discovery call.
		auth, err = middleware.NewGenericAuthenticator(ts)
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

func (c *Connection) jwtProfileTokenSourceWithHTTPClient(jwtProfileTokenSource middleware.JWTProfileTokenSource) (oauth2.TokenSource, error) {
	if c.httpClient == nil {
		return jwtProfileTokenSource(c.issuer, c.scopes)
	}

	originalDefaultClient := http.DefaultClient
	originalDefaultTransport := http.DefaultTransport

	http.DefaultClient = c.httpClient
	if c.httpClient.Transport != nil {
		http.DefaultTransport = c.httpClient.Transport
	}
	defer func() {
		http.DefaultClient = originalDefaultClient
		http.DefaultTransport = originalDefaultTransport
	}()

	return jwtProfileTokenSource(c.issuer, c.scopes)
}

func transportOption(api string, insecure bool, insecureSkipVerify bool, caCertPool *x509.CertPool) (grpc.DialOption, error) {
	if insecure {
		//nolint:staticcheck // WithInsecure is used for compatibility; callers control security.
		return grpc.WithInsecure(), nil
	}
	certs, err := transportCredentials(api, insecureSkipVerify, caCertPool)
	if err != nil {
		return nil, err
	}
	return grpc.WithTransportCredentials(certs), nil
}

func transportCredentials(api string, insecureSkipVerify bool, caCertPool *x509.CertPool) (credentials.TransportCredentials, error) {
	var ca *x509.CertPool
	if caCertPool != nil {
		ca = caCertPool
	} else {
		var err error
		ca, err = x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		if ca == nil {
			ca = x509.NewCertPool()
		}
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
// For more advanced TLS configurations (e.g., custom CA), use WithHTTPClient instead.
func WithInsecureSkipVerifyTLS() func(*Connection) error {
	return func(client *Connection) error {
		client.insecureSkipVerify = true
		return nil
	}
}

// WithHTTPClient sets a custom HTTP client for OIDC discovery and token requests.
// This allows full control over TLS configuration, including custom CAs, timeouts, and proxies.
// When set, this takes precedence over WithInsecureSkipVerifyTLS and WithTrustStore for HTTP transport.
// Note: This does not affect gRPC transport TLS settings.
func WithHTTPClient(httpClient *http.Client) func(*Connection) error {
	return func(client *Connection) error {
		client.httpClient = httpClient
		return nil
	}
}

// WithTrustStore adds custom CA certificates to the trust store for both gRPC and HTTP transports.
// The certificates should be PEM-encoded. This is useful when connecting to servers using
// certificates signed by a private CA (e.g., in development or enterprise environments).
// The provided certificates are appended to the system certificate pool.
// For HTTP transport, this is ignored if WithHTTPClient is also set (user has full control).
func WithTrustStore(caCerts ...[]byte) func(*Connection) error {
	return func(client *Connection) error {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		for _, cert := range caCerts {
			if !pool.AppendCertsFromPEM(cert) {
				return errors.New("failed to append CA certificate to trust store")
			}
		}
		client.caCertPool = pool
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

// headerRoundTripper wraps an http.RoundTripper to add custom headers to each request
type headerRoundTripper struct {
	rt      http.RoundTripper
	headers map[string]string
}

func (h *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	newReq := *req
	newReq.Header = make(http.Header, len(req.Header))
	for k, s := range req.Header {
		newReq.Header[k] = s
	}
	for k, v := range h.headers {
		newReq.Header.Set(k, v)
	}
	return h.rt.RoundTrip(&newReq)
}

// createDefaultJWTProfileTokenSource creates a JWT profile token source that reads
// the key file from the ZITADEL_KEY_PATH environment variable and optionally uses
// a custom HTTP client for OIDC discovery and token fetching.
func createDefaultJWTProfileTokenSource(ctx context.Context, httpClient *http.Client) middleware.JWTProfileTokenSource {
	return func(issuer string, scopes []string) (oauth2.TokenSource, error) {
		keyPath := middleware.OSKeyPath()
		keyData, err := client.ConfigFromKeyFile(keyPath)
		if err != nil {
			return nil, err
		}

		if httpClient != nil {
			return profile.NewJWTProfileTokenSource(ctx, issuer, keyData.UserID, keyData.KeyID, keyData.Key, scopes, profile.WithHTTPClient(httpClient))
		}
		return profile.NewJWTProfileTokenSource(ctx, issuer, keyData.UserID, keyData.KeyID, keyData.Key, scopes)
	}
}
