package mockzitadel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/madflojo/testcerts"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/system"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

type Options struct {
	ExpectedHeaders map[string]string
}

func WithServer(t *testing.T, opts Options, fn func(issuerURL, apiAddr string)) {
	t.Helper()

	tlsConfig := newTLSConfig(t)
	server := httptest.NewUnstartedServer(nil)
	server.TLS = tlsConfig.Clone()
	server.Config.Handler = newOIDCHandler(t, func() string { return server.URL }, opts.ExpectedHeaders)
	server.StartTLS()
	t.Cleanup(server.Close)

	apiAddr := startGRPCServer(t, tlsConfig, opts.ExpectedHeaders)

	fn(server.URL, apiAddr)
}

func newOIDCHandler(t *testing.T, issuer func() string, expectedHeaders map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range expectedHeaders {
			require.Equal(t, v, r.Header.Get(k))
		}

		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                 issuer(),
				"token_endpoint":         issuer() + "/oauth/v2/token",
				"authorization_endpoint": issuer() + "/oauth/v2/authorize",
				"jwks_uri":               issuer() + "/.well-known/jwks.json",
			})
			require.NoError(t, err)
		case "/oauth/v2/token":
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(map[string]any{
				"access_token": "dummy-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
			require.NoError(t, err)
		default:
			http.NotFound(w, r)
		}
	})
}

func newTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	ca := testcerts.NewCA()
	kp, err := ca.NewKeyPairFromConfig(testcerts.KeyPairConfig{
		Domains:     []string{"localhost"},
		IPAddresses: []string{"127.0.0.1"},
		CommonName:  "localhost",
	})
	require.NoError(t, err)

	serverTLS, err := kp.ConfigureTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12,
	})
	require.NoError(t, err)

	return serverTLS
}

func startGRPCServer(t *testing.T, tlsConfig *tls.Config, expectedHeaders map[string]string) string {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	serverHandler := func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
		if len(expectedHeaders) > 0 {
			md, ok := metadata.FromIncomingContext(ctx)
			require.True(t, ok)
			for k, v := range expectedHeaders {
				require.Equal(t, []string{v}, md.Get(k))
			}
		}
		return &system.HealthzResponse{}, nil
	}

	creds := credentials.NewTLS(tlsConfig.Clone())

	s := grpc.NewServer(grpc.Creds(creds))

	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "zitadel.system.v1.SystemService",
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Healthz",
				Handler:    serverHandler,
			},
		},
		Streams:  []grpc.StreamDesc{},
		Metadata: "zitadel/system/v1/system.proto",
	}, nil)

	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.GracefulStop)

	return lis.Addr().String()
}
