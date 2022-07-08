package middleware

import (
	"context"

	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"github.com/zitadel/oidc/pkg/client/rs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zitadel/zitadel-go/v2/pkg/api/middleware"
)

type IntrospectionInterceptor struct {
	resourceServer rs.ResourceServer
}

//NewIntrospectionInterceptor intercepts every call and checks for a correct Bearer token using OAuth2 introspection
//by sending the token to the introspection endpoint)
func NewIntrospectionInterceptor(issuer, keyPath string) (*IntrospectionInterceptor, error) {
	resourceServer, err := rs.NewResourceServerFromKeyFile(issuer, keyPath)
	if err != nil {
		return nil, err
	}
	return &IntrospectionInterceptor{
		resourceServer: resourceServer,
	}, nil
}

func (interceptor *IntrospectionInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		err = interceptor.introspect(ctx)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func (interceptor *IntrospectionInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		err := interceptor.introspect(stream.Context())
		if err != nil {
			return err
		}
		return handler(srv, stream)
	}
}

func (interceptor *IntrospectionInterceptor) introspect(ctx context.Context) error {
	err := middleware.Introspect(ctx, metautils.ExtractIncoming(ctx).Get("authorization"), interceptor.resourceServer)
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	return nil
}
