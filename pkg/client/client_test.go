package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	oidcclient "github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/internal/testidp"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestClient_TransportConfiguration_Table(t *testing.T) {
	tests := []struct {
		name             string
		useTLS           bool
		clientOptsFunc   func(host string, port uint16) []zitadel.Option
		expectError      bool
		expectHTTPHeader bool
		expectGRPCHeader bool
	}{
		{
			name:   "1_InsecureSkipVerify_Success",
			useTLS: true,
			clientOptsFunc: func(host string, port uint16) []zitadel.Option {
				return []zitadel.Option{
					zitadel.WithPort(port),
					zitadel.WithInsecureSkipVerifyTLS(),
				}
			},
			expectError: false,
		},
		{
			name:   "2_Plaintext_HTTP_Success",
			useTLS: false,
			clientOptsFunc: func(host string, port uint16) []zitadel.Option {
				return []zitadel.Option{
					zitadel.WithInsecure(strconv.Itoa(int(port))),
				}
			},
			expectError: false,
		},
		{
			name:   "3_CustomHeaders_Propagate",
			useTLS: true,
			clientOptsFunc: func(host string, port uint16) []zitadel.Option {
				return []zitadel.Option{
					zitadel.WithPort(port),
					zitadel.WithInsecureSkipVerifyTLS(),
					zitadel.WithTransportHeader("x-foo", "bar"),
				}
			},
			expectError:      false,
			expectHTTPHeader: true,
			expectGRPCHeader: true,
		},
		{
			name:   "4_DefaultSecure_FailsOnSelfSigned",
			useTLS: true,
			clientOptsFunc: func(host string, port uint16) []zitadel.Option {
				return []zitadel.Option{
					zitadel.WithPort(port),
				}
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *httptest.Server
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.expectHTTPHeader {
					assert.Equal(t, "bar", r.Header.Get("x-foo"))
				}
				w.WriteHeader(http.StatusOK)
			})

			if tt.useTLS {
				server = httptest.NewTLSServer(handler)
			} else {
				server = httptest.NewServer(handler)
			}
			defer server.Close()

			listener, err := net.Listen("tcp", "localhost:0")
			require.NoError(t, err)

			var srvOpts []grpc.ServerOption
			if tt.useTLS {
				cert := server.TLS.Certificates[0]
				srvOpts = append(srvOpts, grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}})))
			}

			srvOpts = append(srvOpts, grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
				if tt.expectGRPCHeader {
					md, _ := metadata.FromIncomingContext(ctx)
					vals := md.Get("x-foo")
					if assert.NotEmpty(t, vals) {
						assert.Equal(t, "bar", vals[0])
					}
				}
				return handler(ctx, req)
			}))

			grpcServer := grpc.NewServer(srvOpts...)
			go func() { _ = grpcServer.Serve(listener) }()
			defer grpcServer.Stop()

			host, portStr, _ := net.SplitHostPort(listener.Addr().String())
			port, _ := strconv.Atoi(portStr)

			opts := tt.clientOptsFunc(host, uint16(port))

			mockSource := func(ctx context.Context, issuer string) (oauth2.TokenSource, error) {
				httpClient, ok := ctx.Value(oauth2.HTTPClient).(*http.Client)
				if !ok {
					httpClient = http.DefaultClient
				}

				req, _ := http.NewRequest("GET", server.URL, nil)
				resp, err := httpClient.Do(req)
				if err != nil {
					return nil, err
				}
				assert.NoError(t, resp.Body.Close())
				return nil, nil
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			c, err := New(ctx, zitadel.New(host, opts...),
				WithAuth(mockSource),
				//nolint:staticcheck // WithBlock is used in tests to ensure connection attempts block as expected.
				WithGRPCDialOptions(grpc.WithBlock()),
			)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)

				err = c.connection.Invoke(ctx, "/test.Service/TestMethod", nil, nil)
				if err != nil {
					st, ok := status.FromError(err)
					require.True(t, ok)
					assert.Equal(t, codes.Unimplemented, st.Code())
				} else {
					assert.NoError(t, err)
				}

				require.NoError(t, c.Close())
			}
		})
	}
}

func TestClient_GetValidToken(t *testing.T) {
	tests := []struct {
		name          string
		tokenSource   oauth2.TokenSource
		expectedToken string
		expectedError bool
	}{
		{
			name: "valid_token",
			tokenSource: oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: "test-token-123",
				TokenType:   "Bearer",
			}),
			expectedToken: "test-token-123",
			expectedError: false,
		},
		{
			name:          "nil_token_source",
			tokenSource:   nil,
			expectedToken: "",
			expectedError: false,
		},
		{
			name: "token_source_error",
			tokenSource: &mockTokenSource{
				token: nil,
				err:   errors.New("token generation failed"),
			},
			expectedToken: "",
			expectedError: true,
		},
		{
			name: "empty_token",
			tokenSource: oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: "",
				TokenType:   "Bearer",
			}),
			expectedToken: "",
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{
				tokenSource: tt.tokenSource,
			}

			token, err := client.GetValidToken()

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedToken, token)
			}
		})
	}
}

type mockTokenSource struct {
	token *oauth2.Token
	err   error
	calls int
}

func (m *mockTokenSource) Token() (*oauth2.Token, error) {
	m.calls++
	return m.token, m.err
}

func TestClient_TokenSourceReused(t *testing.T) {
	underlyingSource := &mockTokenSource{
		token: &oauth2.Token{
			AccessToken: "cached-token-123",
			Expiry:      time.Now().Add(1 * time.Hour),
		},
	}
	initCount := 0
	initSource := func(ctx context.Context, issuer string) (oauth2.TokenSource, error) {
		initCount++
		return underlyingSource, nil
	}

	ctx := context.Background()
	c, err := New(ctx, zitadel.New("localhost", zitadel.WithInsecure("8080")),
		WithAuth(initSource),
	)
	require.NoError(t, err)
	defer c.Close()

	assert.Equal(t, 1, initCount)

	tok1, err := c.GetValidToken()
	require.NoError(t, err)
	assert.Equal(t, "cached-token-123", tok1)

	tok2, err := c.GetValidToken()
	require.NoError(t, err)
	assert.Equal(t, "cached-token-123", tok2)

	assert.Equal(t, 1, underlyingSource.calls)
}

// TestNew_Authentication_AppliesTransportOptionsToHTTP verifies that the TLS and header options also apply
// to the OIDC discovery and token requests made by the authentication initializers.
func TestNew_Authentication_AppliesTransportOptionsToHTTP(t *testing.T) {
	keyData := testidp.KeyFileJSON(t)
	keyPath := filepath.Join(t.TempDir(), "key.json")
	require.NoError(t, os.WriteFile(keyPath, keyData, 0o600))
	keyFile, err := ConfigFromKeyFileData(keyData)
	require.NoError(t, err)

	tests := []struct {
		name string
		auth TokenSourceInitializer
	}{
		{name: "AuthenticationJWTProfile", auth: AuthenticationJWTProfile(keyFile)},
		{
			name: "JWTAuthentication",
			auth: JWTAuthentication(&oidcclient.KeyFile{UserID: keyFile.UserID, KeyID: keyFile.KeyID, Key: string(keyFile.Key)}),
		},
		{name: "DefaultServiceUserAuthentication", auth: DefaultServiceUserAuthentication(keyPath)},
		{name: "PasswordAuthentication", auth: PasswordAuthentication("user", "secret")},
	}
	for _, tt := range tests {
		for _, useTLS := range []bool{false, true} {
			t.Run(tt.name+"/tls="+strconv.FormatBool(useTLS), func(t *testing.T) {
				idp := testidp.New(t, useTLS)
				_, port, err := net.SplitHostPort(idp.Listener.Addr().String())
				require.NoError(t, err)

				opts := []zitadel.Option{zitadel.WithTransportHeader("x-foo", "bar")}
				if useTLS {
					portNumber, err := strconv.Atoi(port)
					require.NoError(t, err)
					opts = append(opts, zitadel.WithPort(uint16(portNumber)), zitadel.WithInsecureSkipVerifyTLS())
				} else {
					opts = append(opts, zitadel.WithInsecure(port))
				}

				c, err := New(context.Background(), zitadel.New("127.0.0.1", opts...), WithAuth(tt.auth))
				require.NoError(t, err)
				_, err = c.tokenSource.Token()
				require.NoError(t, err)

				assert.Equal(t, "bar", idp.Header(testidp.DiscoveryPath, "x-foo"))
				assert.Equal(t, "bar", idp.Header(testidp.TokenPath, "x-foo"))
			})
		}
	}
}

// TestNew_KeepsAnInjectedHTTPClient verifies that a client in the context, e.g. one that trusts a
// private CA, keeps being used for the OIDC requests next to the transport options.
func TestNew_KeepsAnInjectedHTTPClient(t *testing.T) {
	keyFile, err := ConfigFromKeyFileData(testidp.KeyFileJSON(t))
	require.NoError(t, err)
	idp := testidp.New(t, true)
	_, port, err := net.SplitHostPort(idp.Listener.Addr().String())
	require.NoError(t, err)
	portNumber, err := strconv.Atoi(port)
	require.NoError(t, err)
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, idp.Client())

	c, err := New(ctx,
		zitadel.New("127.0.0.1", zitadel.WithPort(uint16(portNumber)), zitadel.WithTransportHeader("x-foo", "bar")),
		WithAuth(AuthenticationJWTProfile(keyFile)),
	)
	require.NoError(t, err)
	_, err = c.tokenSource.Token()
	require.NoError(t, err)

	assert.Equal(t, "bar", idp.Header(testidp.DiscoveryPath, "x-foo"))
	assert.Equal(t, "bar", idp.Header(testidp.TokenPath, "x-foo"))
}
