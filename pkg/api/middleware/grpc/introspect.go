package middleware

import (
	"context"

	"github.com/caos/oidc/pkg/client/rs"
	"github.com/caos/oidc/pkg/oidc"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/caos/zitadel-go/pkg/api/middleware"
)

type IntrospectionInterceptor struct {
	resourceServer rs.ResourceServer
	ignoredPaths   []string
	introspectOpts []func(oidc.IntrospectionResponse) error
}

func WithIgnoredPaths(paths ...string) func(*IntrospectionInterceptor) {
	return func(interceptor *IntrospectionInterceptor) {
		interceptor.ignoredPaths = paths
	}
}

func WithIntrospectionOptions(opts ...func(oidc.IntrospectionResponse) error) func(*IntrospectionInterceptor) {
	return func(interceptor *IntrospectionInterceptor) {
		interceptor.introspectOpts = opts
	}
}

//NewIntrospectionInterceptor intercepts every call and checks for a correct Bearer token using OAuth2 introspection
//by sending the token to the introspection endpoint)
func NewIntrospectionInterceptor(issuer, keyPath string, opts ...func(*IntrospectionInterceptor)) (*IntrospectionInterceptor, error) {
	resourceServer, err := rs.NewResourceServerFromKeyFile(issuer, keyPath)
	if err != nil {
		return nil, err
	}
	interceptor := &IntrospectionInterceptor{
		resourceServer: resourceServer,
	}
	for _, opt := range opts {
		opt(interceptor)
	}
	return interceptor, nil
}

func (interceptor *IntrospectionInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		for _, path := range interceptor.ignoredPaths {
			if path == info.FullMethod {
				return handler(ctx, req)
			}
		}
		ctx, err = interceptor.introspect(ctx)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func (interceptor *IntrospectionInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		_, err := interceptor.introspect(stream.Context())
		if err != nil {
			return err
		}
		return handler(srv, stream)
	}
}

func (interceptor *IntrospectionInterceptor) introspect(ctx context.Context) (context.Context, error) {
	response, err := middleware.Introspect(ctx, metautils.ExtractIncoming(ctx).Get("authorization"), interceptor.resourceServer, interceptor.introspectOpts...)
	if err != nil {
		return ctx, status.Error(codes.Unauthenticated, err.Error())
	}
	return context.WithValue(ctx, middleware.INTROSPECTION, response), nil
}
