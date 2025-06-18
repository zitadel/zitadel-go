package zitadel

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
// the default issuer and api endpoint values in the Connection struct. This
// ensures that the client can be configured to connect to non-standard or
// custom-hosted ZITADEL instances.
func TestWithCustomURL(t *testing.T) {
	api := startMockGRPCServer(t)
	conn, err := NewConnection(context.Background(), "default-issuer", api, nil,
		WithCustomURL("https://my-custom-issuer.com", "my-custom-api.com:443"),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{})),
	)
	require.NoError(t, err, "NewConnection should not fail")

	assert.Equal(t, "https://my-custom-issuer.com", conn.issuer)
	assert.Equal(t, "my-custom-api.com:443", conn.api)
}

// TestWithTokenSource verifies that the WithTokenSource option correctly sets
// a generic oauth2.TokenSource on the Connection struct. This is the primary
// mechanism for flexible client authentication, allowing methods like Client
// Credentials or Personal Access Tokens.
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
// internal insecure flag to true. This flag is later used by the connection
// logic to establish a gRPC connection without requiring transport security
// (TLS), a setting crucial for local development or testing environments.
func TestWithInsecure(t *testing.T) {
	api := startMockGRPCServer(t)

	conn, err := NewConnection(context.Background(), "issuer", api, nil,
		WithInsecure(),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{})),
	)

	require.NoError(t, err, "NewConnection should not fail")
	assert.True(t, conn.insecure)
}

// TestWithUnaryInterceptors verifies that the WithUnaryInterceptors option
// correctly appends custom gRPC interceptors to the connection's list of
// unary interceptors. This ensures that users of the SDK can extend the
// client's behavior with their own logic, such as custom logging or tracing.
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
// correctly appends custom gRPC interceptors to the connection's list of
// stream interceptors, mirroring the functionality for unary interceptors.
func TestWithStreamInterceptors(t *testing.T) {
	api := startMockGRPCServer(t)
	conn, err := NewConnection(context.Background(), "issuer", api, nil,
		WithStreamInterceptors(func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			return nil, status.Error(codes.Unimplemented, "dummy interceptor")
		}, func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			return nil, status.Error(codes.Unimplemented, "dummy interceptor")
		}),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{})),
	)

	require.NoError(t, err, "NewConnection should not fail")
	assert.Len(t, conn.streamInterceptors, 3)
}

// TestWithDialOptions verifies that the WithDialOptions option correctly
// appends custom gRPC dial options. These options are passed directly to the
// underlying grpc.Dial call, allowing for advanced configuration of the gRPC
// connection itself.
func TestWithDialOptions(t *testing.T) {
	api := startMockGRPCServer(t)
	conn, err := NewConnection(context.Background(), "issuer", api, nil,
		WithDialOptions(grpc.WithUserAgent("my-test-agent/1.0")),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{})),
	)

	require.NoError(t, err, "NewConnection should not fail")
	assert.Len(t, conn.dialOptions, 1)
}
