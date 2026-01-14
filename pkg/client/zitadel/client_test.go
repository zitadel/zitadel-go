package zitadel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/zitadel-go/v3/pkg/client/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/internal/mockzitadel"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/internal/testutil"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/system"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
)

func TestInsecureSkipVerifyTLS_HTTPDiscovery(t *testing.T) {
	keyPath := writeServiceAccountKey(t)

	tests := []struct {
		name               string
		opts               []Option
		authOptions        []Option
		expectedErr        string
		expectedHTTPHeader map[string]string
		expectedOrgID      string
	}{
		{
			name:        "rejects self-signed without skip verify",
			authOptions: []Option{WithJWTProfileTokenSource(middleware.JWTProfileFromPath(context.Background(), keyPath))},
			expectedErr: "certificate",
		},
		{
			name: "accepts self-signed with skip verify and propagates headers",
			opts: []Option{
				WithInsecureSkipVerifyTLS(),
				WithTransportHeader("X-Test", "value"),
			},
			authOptions: []Option{
				WithJWTProfileTokenSource(middleware.JWTProfileFromPath(context.Background(), keyPath))},
			expectedHTTPHeader: map[string]string{"X-Test": "value"},
		},
		{
			name: "custom token source and interceptors with skip verify",
			opts: []Option{
				WithInsecureSkipVerifyTLS(),
				WithTransportHeader("X-Trace", "trace"),
				WithUnaryInterceptors(testutil.PassThroughUnary(), testutil.PassThroughUnary()),
				WithStreamInterceptors(testutil.PassThroughStream()),
				WithDialOptions(grpc.WithUserAgent("test-agent/1.0")),
				WithOrgID("org-123"),
			},
			authOptions: []Option{
				WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token", TokenType: "Bearer"})),
			},
			expectedHTTPHeader: map[string]string{"X-Trace": "trace"},
			expectedOrgID:      "org-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockzitadel.WithServer(t, mockzitadel.Options{ExpectedHeaders: tt.expectedHTTPHeader}, func(issuerURL, grpcAddr string) {
				opts := append([]Option{}, tt.opts...)
				opts = append(opts, tt.authOptions...)

				conn, err := NewConnection(context.Background(), issuerURL, grpcAddr, []string{"openid"}, opts...)
				if tt.expectedErr != "" {
					require.Error(t, err)
					assert.Contains(t, err.Error(), tt.expectedErr)
					return
				}

				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, conn.Close()) })
				if tt.expectedOrgID != "" {
					assert.Equal(t, tt.expectedOrgID, conn.orgID)
				}

				client := system.NewSystemServiceClient(conn.ClientConn)

				res, err := client.Healthz(context.Background(), &system.HealthzRequest{})
				require.NoError(t, err, "gRPC Healthz call failed")
				assert.NotNil(t, res)
			})
		})
	}
}

func TestWithTrustStore(t *testing.T) {
	keyPath := writeServiceAccountKey(t)

	tests := []struct {
		name               string
		opts               func(caCert []byte) []Option
		authOptions        []Option
		expectedErr        string
		expectedHTTPHeader map[string]string
	}{
		{
			name: "accepts server cert with custom CA in trust store",
			opts: func(caCert []byte) []Option {
				return []Option{
					WithTrustStore(caCert),
					WithTransportHeader("X-Custom-CA", "true"),
				}
			},
			authOptions: []Option{
				WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token", TokenType: "Bearer"})),
			},
			expectedHTTPHeader: map[string]string{"X-Custom-CA": "true"},
		},
		{
			name: "accepts server cert with custom CA and JWT profile auth",
			opts: func(caCert []byte) []Option {
				return []Option{
					WithTrustStore(caCert),
				}
			},
			authOptions:        []Option{WithJWTProfileTokenSource(middleware.JWTProfileFromPath(context.Background(), keyPath))},
			expectedHTTPHeader: map[string]string{},
		},
		{
			name: "rejects invalid CA certificate",
			opts: func(caCert []byte) []Option {
				return []Option{
					WithTrustStore([]byte("not a valid certificate")),
				}
			},
			authOptions: []Option{
				WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token", TokenType: "Bearer"})),
			},
			expectedErr: "failed to append CA certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockzitadel.WithServerInfo(t, mockzitadel.Options{ExpectedHeaders: tt.expectedHTTPHeader}, func(info mockzitadel.ServerInfo) {
				opts := append([]Option{}, tt.opts(info.CACert)...)
				opts = append(opts, tt.authOptions...)

				conn, err := NewConnection(context.Background(), info.IssuerURL, info.APIAddr, []string{"openid"}, opts...)
				if tt.expectedErr != "" {
					require.Error(t, err)
					assert.Contains(t, err.Error(), tt.expectedErr)
					return
				}

				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, conn.Close()) })

				client := system.NewSystemServiceClient(conn.ClientConn)

				res, err := client.Healthz(context.Background(), &system.HealthzRequest{})
				require.NoError(t, err, "gRPC Healthz call failed")
				assert.NotNil(t, res)
			})
		})
	}
}

func TestWithTrustStore_WrongCA(t *testing.T) {
	// This test verifies that using the wrong CA causes TLS verification to fail.
	// The error happens during the gRPC call (not during Dial) because gRPC connections are lazy.
	mockzitadel.WithServerInfo(t, mockzitadel.Options{}, func(info mockzitadel.ServerInfo) {
		wrongCA := generateWrongCA()

		conn, err := NewConnection(context.Background(), info.IssuerURL, info.APIAddr, []string{"openid"},
			WithTrustStore(wrongCA),
			WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token", TokenType: "Bearer"})),
		)
		require.NoError(t, err, "NewConnection should succeed (gRPC Dial is lazy)")
		t.Cleanup(func() { _ = conn.Close() })

		client := system.NewSystemServiceClient(conn.ClientConn)

		// The TLS error happens here, during the actual RPC call
		_, err = client.Healthz(context.Background(), &system.HealthzRequest{})
		require.Error(t, err, "gRPC call should fail due to certificate verification")
		assert.Contains(t, err.Error(), "certificate")
	})
}

func writeServiceAccountKey(t *testing.T) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	keyJSON, err := json.Marshal(map[string]string{
		"type":   "serviceaccount",
		"keyId":  "test-key-id",
		"key":    string(keyPEM),
		"userId": "test-user-id",
	})
	require.NoError(t, err)

	keyPath := t.TempDir() + "/key.json"
	require.NoError(t, os.WriteFile(keyPath, keyJSON, 0600))
	return keyPath
}

// generateWrongCA creates a different CA certificate that was NOT used to sign the server cert
func generateWrongCA() []byte {
	// Generate a new CA key pair
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Wrong CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})
}
