package zitadel

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/zitadel/zitadel-go/v3/pkg/client/internal/testidp"
	"github.com/zitadel/zitadel-go/v3/pkg/client/middleware"
)

// startMockGRPCServer sets up a minimal, non-functional gRPC server that
// successfully accepts connections. This allows us to test the NewConnection
// function's logic without it failing on `grpc.Dial`.
func startMockGRPCServer(t *testing.T) string {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "mock server failed to listen")

	s := grpc.NewServer()

	go func() {
		_ = s.Serve(lis)
	}()

	t.Cleanup(s.GracefulStop)

	return lis.Addr().String()
}

// TestWithCustomURL verifies that the WithCustomURL option correctly overrides
// the default issuer and api endpoint values in the Connection struct.
func TestWithCustomURL(t *testing.T) {
	api := startMockGRPCServer(t)
	customIssuer := "https://my-custom-issuer.com"
	customAPI := "my-custom-api.com:443"

	conn, err := NewConnection(context.Background(), "default-issuer", api, nil,
		WithCustomURL(customIssuer, customAPI),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{})),
	)
	require.NoError(t, err, "NewConnection should not fail")

	assert.Equal(t, customIssuer, conn.issuer)
	assert.Equal(t, customAPI, conn.api)
}

// TestWithTokenSource verifies that the WithTokenSource option correctly sets
// a generic oauth2.TokenSource on the Connection struct.
func TestWithTokenSource(t *testing.T) {
	api := startMockGRPCServer(t)
	mockTokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"})

	conn, err := NewConnection(context.Background(), "issuer", api, nil,
		WithTokenSource(mockTokenSource),
	)
	require.NoError(t, err, "NewConnection should not fail")

	assert.Equal(t, mockTokenSource, conn.tokenSource)
}

// TestWithInsecure verifies that the WithInsecure option correctly sets the
// internal insecure flag to true.
func TestWithInsecure(t *testing.T) {
	api := startMockGRPCServer(t)

	conn, err := NewConnection(context.Background(), "issuer", api, nil,
		WithInsecure(),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{})),
	)
	require.NoError(t, err, "NewConnection should not fail")

	assert.True(t, conn.insecure)
}

// TestWithInsecureSkipVerifyTLS verifies that the WithInsecureSkipVerifyTLS option
// correctly sets the flag on the connection.
func TestWithInsecureSkipVerifyTLS(t *testing.T) {
	api := startMockGRPCServer(t)

	conn, err := NewConnection(context.Background(), "issuer", api, nil,
		WithInsecureSkipVerifyTLS(),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{})),
	)
	require.NoError(t, err, "NewConnection should not fail")

	assert.True(t, conn.insecureSkipVerify)
}

// TestWithTransportHeader verifies that transport headers are stored on the connection.
func TestWithTransportHeader(t *testing.T) {
	api := startMockGRPCServer(t)

	conn, err := NewConnection(context.Background(), "issuer", api, nil,
		WithTransportHeader("x-test", "value"),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{})),
	)
	require.NoError(t, err, "NewConnection should not fail")

	assert.Equal(t, "value", conn.transportHeaders["x-test"])
}

// TestWithUnaryInterceptors verifies that the WithUnaryInterceptors option
// correctly appends custom gRPC interceptors to the connection's list.
func TestWithUnaryInterceptors(t *testing.T) {
	api := startMockGRPCServer(t)
	dummyInterceptor := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return status.Error(codes.Unimplemented, "dummy interceptor")
	}

	conn, err := NewConnection(context.Background(), "issuer", api, nil,
		WithUnaryInterceptors(dummyInterceptor, dummyInterceptor),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{})),
	)
	require.NoError(t, err, "NewConnection should not fail")

	assert.Len(t, conn.unaryInterceptors, 3)
}

// TestWithStreamInterceptors verifies that the WithStreamInterceptors option
// correctly appends custom gRPC interceptors to the connection's list.
func TestWithStreamInterceptors(t *testing.T) {
	api := startMockGRPCServer(t)
	dummyInterceptor := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		return nil, status.Error(codes.Unimplemented, "dummy interceptor")
	}

	conn, err := NewConnection(context.Background(), "issuer", api, nil,
		WithStreamInterceptors(dummyInterceptor, dummyInterceptor),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{})),
	)
	require.NoError(t, err, "NewConnection should not fail")

	assert.Len(t, conn.streamInterceptors, 3)
}

// TestWithDialOptions verifies that the WithDialOptions option correctly
// appends custom gRPC dial options.
func TestWithDialOptions(t *testing.T) {
	api := startMockGRPCServer(t)
	dummyDialOption := grpc.WithUserAgent("my-test-agent/1.0")

	conn, err := NewConnection(context.Background(), "issuer", api, nil,
		WithDialOptions(dummyDialOption),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{})),
	)
	require.NoError(t, err, "NewConnection should not fail")

	assert.Len(t, conn.dialOptions, 1)
}

// TestNewConnection_JWTProfile_AppliesTransportOptionsToHTTP verifies that the TLS and header options
// also apply to the OIDC discovery and token requests made for the JWT profile authentication.
func TestNewConnection_JWTProfile_AppliesTransportOptionsToHTTP(t *testing.T) {
	keyFile := testidp.KeyFileJSON(t)
	keyPath := filepath.Join(t.TempDir(), "key.json")
	require.NoError(t, os.WriteFile(keyPath, keyFile, 0o600))

	tests := []struct {
		name    string
		useTLS  bool
		options func(t *testing.T) []Option
	}{
		{
			name: "context aware helper",
			options: func(t *testing.T) []Option {
				return []Option{
					WithInsecure(),
					WithJWTProfileTokenSourceContext(middleware.JWTProfileFromFileDataContext(keyFile)),
				}
			},
		},
		{
			name: "key file from the environment",
			options: func(t *testing.T) []Option {
				t.Setenv(middleware.ZitadelKeyPath, keyPath)
				return []Option{WithInsecure()}
			},
		},
		{
			name:   "self-signed certificate",
			useTLS: true,
			options: func(t *testing.T) []Option {
				return []Option{
					WithInsecureSkipVerifyTLS(),
					WithJWTProfileTokenSourceContext(middleware.JWTProfileFromFileDataContext(keyFile)),
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := testidp.New(t, tt.useTLS)
			options := append(tt.options(t), WithTransportHeader("x-foo", "bar"))

			conn, err := NewConnection(context.Background(), idp.URL, startMockGRPCServer(t), nil, options...)
			require.NoError(t, err)

			// the token is requested before the call is made, so the call itself is expected to fail
			_ = conn.Invoke(context.Background(), "/zitadel.test.Service/Method", &emptypb.Empty{}, &emptypb.Empty{})

			assert.Equal(t, "bar", idp.Header(testidp.DiscoveryPath, "x-foo"))
			assert.Equal(t, "bar", idp.Header(testidp.TokenPath, "x-foo"))
		})
	}
}

// TestWithJWTProfileTokenSourceContext_ReplacesTheLegacyProvider verifies that the last of the two options wins.
func TestWithJWTProfileTokenSourceContext_ReplacesTheLegacyProvider(t *testing.T) {
	legacy := WithJWTProfileTokenSource(middleware.JWTProfileFromFileData(context.Background(), nil))
	withContext := WithJWTProfileTokenSourceContext(middleware.JWTProfileFromFileDataContext(nil))

	c := &Connection{}
	require.NoError(t, legacy(c))
	assert.NotNil(t, c.jwtProfileTokenSource)
	assert.Nil(t, c.jwtProfileTokenSourceContext)

	require.NoError(t, withContext(c))
	assert.Nil(t, c.jwtProfileTokenSource)
	assert.NotNil(t, c.jwtProfileTokenSourceContext)

	require.NoError(t, legacy(c))
	assert.NotNil(t, c.jwtProfileTokenSource)
	assert.Nil(t, c.jwtProfileTokenSourceContext)
}

// TestNewConnection_JWTProfileProvider verifies which provider authenticates the connection,
// and that the providers of both options are called with the issuer and the scopes.
func TestNewConnection_JWTProfileProvider(t *testing.T) {
	scopes := []string{"openid", "scope"}
	static := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "token", TokenType: "Bearer"})

	tests := []struct {
		name            string
		options         func(legacy middleware.JWTProfileTokenSource, withContext middleware.JWTProfileTokenSourceContext) []Option
		expectLegacy    int
		expectWithCtx   int
		expectedErrText string
	}{
		{
			name: "the legacy provider is called with the issuer and the scopes",
			options: func(legacy middleware.JWTProfileTokenSource, _ middleware.JWTProfileTokenSourceContext) []Option {
				return []Option{WithJWTProfileTokenSource(legacy)}
			},
			expectLegacy: 1,
		},
		{
			name: "the context provider is called with the issuer and the scopes",
			options: func(_ middleware.JWTProfileTokenSource, withContext middleware.JWTProfileTokenSourceContext) []Option {
				return []Option{WithJWTProfileTokenSourceContext(withContext)}
			},
			expectWithCtx: 1,
		},
		{
			name: "the last of both providers wins, the legacy one",
			options: func(legacy middleware.JWTProfileTokenSource, withContext middleware.JWTProfileTokenSourceContext) []Option {
				return []Option{WithJWTProfileTokenSourceContext(withContext), WithJWTProfileTokenSource(legacy)}
			},
			expectLegacy: 1,
		},
		{
			name: "the last of both providers wins, the context one",
			options: func(legacy middleware.JWTProfileTokenSource, withContext middleware.JWTProfileTokenSourceContext) []Option {
				return []Option{WithJWTProfileTokenSource(legacy), WithJWTProfileTokenSourceContext(withContext)}
			},
			expectWithCtx: 1,
		},
		{
			name: "a token source takes precedence over the providers",
			options: func(legacy middleware.JWTProfileTokenSource, withContext middleware.JWTProfileTokenSourceContext) []Option {
				return []Option{WithJWTProfileTokenSource(legacy), WithJWTProfileTokenSourceContext(withContext), WithTokenSource(static)}
			},
		},
		{
			name: "a pre-signed JWT takes precedence over the providers",
			options: func(legacy middleware.JWTProfileTokenSource, _ middleware.JWTProfileTokenSourceContext) []Option {
				return []Option{WithJWTProfileTokenSource(legacy), WithJWTDirectTokenSource("jwt")}
			},
		},
		{
			name: "an error of the legacy provider is returned",
			options: func(_ middleware.JWTProfileTokenSource, _ middleware.JWTProfileTokenSourceContext) []Option {
				return []Option{WithJWTProfileTokenSource(func(string, []string) (oauth2.TokenSource, error) {
					return nil, errors.New("legacy failed")
				})}
			},
			expectedErrText: "legacy failed",
		},
		{
			name: "an error of the context provider is returned",
			options: func(_ middleware.JWTProfileTokenSource, _ middleware.JWTProfileTokenSourceContext) []Option {
				return []Option{WithJWTProfileTokenSourceContext(func(context.Context, string, []string) (oauth2.TokenSource, error) {
					return nil, errors.New("context failed")
				})}
			},
			expectedErrText: "context failed",
		},
		{
			name: "a nil legacy provider is ignored next to a token source",
			options: func(_ middleware.JWTProfileTokenSource, _ middleware.JWTProfileTokenSourceContext) []Option {
				return []Option{WithJWTProfileTokenSource(nil), WithTokenSource(static)}
			},
		},
		{
			name: "a nil context provider is ignored next to a pre-signed JWT",
			options: func(_ middleware.JWTProfileTokenSource, _ middleware.JWTProfileTokenSourceContext) []Option {
				return []Option{WithJWTProfileTokenSourceContext(nil), WithJWTDirectTokenSource("jwt")}
			},
		},
		{
			name: "a nil legacy provider alone is an error",
			options: func(_ middleware.JWTProfileTokenSource, _ middleware.JWTProfileTokenSourceContext) []Option {
				return []Option{WithJWTProfileTokenSource(nil)}
			},
			expectedErrText: "no token source",
		},
		{
			name: "a nil context provider alone is an error",
			options: func(_ middleware.JWTProfileTokenSource, _ middleware.JWTProfileTokenSourceContext) []Option {
				return []Option{WithJWTProfileTokenSourceContext(nil)}
			},
			expectedErrText: "no token source",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var legacyCalls, ctxCalls int
			legacy := func(issuer string, s []string) (oauth2.TokenSource, error) {
				legacyCalls++
				assert.Equal(t, "https://issuer.example", issuer)
				assert.Equal(t, scopes, s)
				return static, nil
			}
			withContext := func(_ context.Context, issuer string, s []string) (oauth2.TokenSource, error) {
				ctxCalls++
				assert.Equal(t, "https://issuer.example", issuer)
				assert.Equal(t, scopes, s)
				return static, nil
			}

			_, err := NewConnection(context.Background(), "https://issuer.example", startMockGRPCServer(t), scopes,
				append(tt.options(legacy, withContext), WithInsecure())...)

			if tt.expectedErrText != "" {
				require.ErrorContains(t, err, tt.expectedErrText)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectLegacy, legacyCalls)
			assert.Equal(t, tt.expectWithCtx, ctxCalls)
		})
	}
}

// TestNewConnection_KeepsAnInjectedHTTPClient verifies that a client in the context, e.g. one that
// trusts a private CA, keeps being used for the OIDC requests next to the transport options.
func TestNewConnection_KeepsAnInjectedHTTPClient(t *testing.T) {
	idp := testidp.New(t, true)
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, idp.Client())

	conn, err := NewConnection(ctx, idp.URL, startMockGRPCServer(t), nil,
		WithInsecure(),
		WithTransportHeader("x-foo", "bar"),
		WithJWTProfileTokenSourceContext(middleware.JWTProfileFromFileDataContext(testidp.KeyFileJSON(t))),
	)
	require.NoError(t, err)
	_ = conn.Invoke(context.Background(), "/zitadel.test.Service/Method", &emptypb.Empty{}, &emptypb.Empty{})

	assert.Equal(t, "bar", idp.Header(testidp.DiscoveryPath, "x-foo"))
	assert.Equal(t, "bar", idp.Header(testidp.TokenPath, "x-foo"))
}

// authorityServer starts a gRPC server which records the authority of the last call.
func authorityServer(t *testing.T) (string, func() string) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var mu sync.Mutex
	var authority string
	s := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		md, _ := metadata.FromIncomingContext(stream.Context())
		mu.Lock()
		authority = strings.Join(md.Get(":authority"), ",")
		mu.Unlock()
		return status.Error(codes.Unimplemented, "not implemented")
	}))
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.GracefulStop)
	return lis.Addr().String(), func() string {
		mu.Lock()
		defer mu.Unlock()
		return authority
	}
}

// TestNewConnection_HostHeader verifies that a Host transport header sets the host of the OIDC requests
// and the authority of the gRPC calls.
func TestNewConnection_HostHeader(t *testing.T) {
	idp := testidp.New(t, false)
	api, authority := authorityServer(t)

	conn, err := NewConnection(context.Background(), idp.URL, api, nil,
		WithInsecure(),
		WithTransportHeader("Host", "external.example"),
		WithJWTProfileTokenSourceContext(middleware.JWTProfileFromFileDataContext(testidp.KeyFileJSON(t))),
	)
	require.NoError(t, err)
	_ = conn.Invoke(context.Background(), "/zitadel.test.Service/Method", &emptypb.Empty{}, &emptypb.Empty{})

	assert.Equal(t, "external.example", idp.Host(testidp.DiscoveryPath))
	assert.Equal(t, "external.example", idp.Host(testidp.TokenPath))
	assert.Equal(t, "external.example", authority())
}

// TestNewConnection_WithoutHostHeader_KeepsTheAuthority verifies that the authority is the dialed address unless
// a Host header is set, and that a dial option overrides it.
func TestNewConnection_WithoutHostHeader_KeepsTheAuthority(t *testing.T) {
	static := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "token", TokenType: "Bearer"})

	api, authority := authorityServer(t)
	conn, err := NewConnection(context.Background(), "https://issuer.example", api, nil, WithInsecure(), WithTokenSource(static))
	require.NoError(t, err)
	_ = conn.Invoke(context.Background(), "/zitadel.test.Service/Method", &emptypb.Empty{}, &emptypb.Empty{})
	assert.Equal(t, api, authority())

	api, authority = authorityServer(t)
	conn, err = NewConnection(context.Background(), "https://issuer.example", api, nil, WithInsecure(), WithTokenSource(static),
		WithTransportHeader("Host", "external.example"), WithDialOptions(grpc.WithAuthority("dial.example")))
	require.NoError(t, err)
	_ = conn.Invoke(context.Background(), "/zitadel.test.Service/Method", &emptypb.Empty{}, &emptypb.Empty{})
	assert.Equal(t, "dial.example", authority(), "an explicit dial option must win over the header")
}

// TestNewConnection_HostHeaderWithTLS verifies that a Host header does not conflict with the TLS server name
// of the gRPC connection, and still sets the host of the OIDC requests.
func TestNewConnection_HostHeaderWithTLS(t *testing.T) {
	idp := testidp.New(t, true)

	conn, err := NewConnection(context.Background(), idp.URL, startMockGRPCServer(t), nil,
		WithInsecureSkipVerifyTLS(),
		WithTransportHeader("Host", "external.example"),
		WithJWTProfileTokenSourceContext(middleware.JWTProfileFromFileDataContext(testidp.KeyFileJSON(t))),
	)
	require.NoError(t, err, "the authority must not conflict with the TLS server name")
	_ = conn.Invoke(context.Background(), "/zitadel.test.Service/Method", &emptypb.Empty{}, &emptypb.Empty{})
	require.NoError(t, conn.Close())

	assert.Equal(t, "external.example", idp.Host(testidp.DiscoveryPath))
	assert.Equal(t, "external.example", idp.Host(testidp.TokenPath))
}
