package middleware

import (
	"context"

	"github.com/caos/oidc/pkg/client/rs"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/caos/zitadel-go/pkg/api/middleware"
)

type IntrospectionInterceptor struct {
	resourceServer rs.ResourceServer
}

//NewIntrospectionInterceptor intercepts every call and checks for a correct Bearer token using OAuth2 introspection
//(sending the token to the introspection endpoint)
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
	auth := metautils.ExtractIncoming(ctx).Get("authorization")
	if auth == "" {
		return status.Error(codes.Unauthenticated, "auth header missing")
	}
	err := middleware.Introspect(ctx, auth, interceptor.resourceServer)
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	return nil
}
