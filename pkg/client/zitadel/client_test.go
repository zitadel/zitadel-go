package zitadel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/zitadel-go/v3/pkg/client/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/internal/mockzitadel"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/system"
	"github.com/zitadel/zitadel-go/v3/pkg/grpc/interceptors"
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
				WithUnaryInterceptors(interceptors.PassThroughUnary(), interceptors.PassThroughUnary()),
				WithStreamInterceptors(interceptors.PassThroughStream()),
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
