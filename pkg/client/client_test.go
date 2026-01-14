package client

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
}

func (m *mockTokenSource) Token() (*oauth2.Token, error) {
	return m.token, m.err
}

func TestClient_WithTrustStore(t *testing.T) {
	tests := []struct {
		name             string
		caCerts          func(serverCert []byte) [][]byte
		expectError      string
		expectHTTPHeader bool
		expectGRPCHeader bool
	}{
		{
			name: "accepts_server_cert_with_custom_CA",
			caCerts: func(serverCert []byte) [][]byte {
				return [][]byte{serverCert}
			},
			expectError:      "",
			expectHTTPHeader: true,
			expectGRPCHeader: true,
		},
		{
			name: "rejects_invalid_CA_certificate",
			caCerts: func(serverCert []byte) [][]byte {
				return [][]byte{[]byte("not a valid certificate")}
			},
			expectError: "failed to append CA certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use httptest's self-signed cert infrastructure
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.expectHTTPHeader {
					assert.Equal(t, "bar", r.Header.Get("x-foo"))
				}
				w.WriteHeader(http.StatusOK)
			}))
			server.StartTLS()
			defer server.Close()

			// Get the CA certificate from the test server
			serverCert := server.Certificate()
			require.NotNil(t, serverCert)

			// Encode to PEM
			caCertPEM := encodeCertToPEM(serverCert.Raw)

			listener, err := net.Listen("tcp", "localhost:0")
			require.NoError(t, err)

			cert := server.TLS.Certificates[0]
			srvOpts := []grpc.ServerOption{
				grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}})),
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

			certs := tt.caCerts(caCertPEM)
			opts := []zitadel.Option{
				zitadel.WithPort(uint16(port)),
				zitadel.WithTrustStore(certs...),
				zitadel.WithTransportHeader("x-foo", "bar"),
			}

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

			if tt.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
			} else {
				require.NoError(t, err)

				err = c.connection.Invoke(ctx, "/test.Service/TestMethod", nil, nil)
				if err != nil {
					st, ok := status.FromError(err)
					require.True(t, ok)
					assert.Equal(t, codes.Unimplemented, st.Code())
				}

				require.NoError(t, c.Close())
			}
		})
	}
}

func encodeCertToPEM(certDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}
