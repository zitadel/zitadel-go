package middleware

import (
	"context"
	"errors"

	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
)

type Interceptor[T authorization.Ctx] struct {
	authorizer *authorization.Authorizer[T]
	checks     map[string][]authorization.CheckOption
}

func New[T authorization.Ctx](authorizer *authorization.Authorizer[T], checks map[string][]authorization.CheckOption) *Interceptor[T] {
	return &Interceptor[T]{
		authorizer: authorizer,
		checks:     checks,
	}
}

// Unary creates a [grpc.UnaryServerInterceptor].
// Ensure to configure the [Interceptor] with the required checks.
// If no checks are provided the interceptor will allow public access to the API.
func (i *Interceptor[T]) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		ctx, err = i.intercept(ctx, info.FullMethod)
		if err != nil {
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
		return handler(ctx, req)
	}
}

// Stream creates a [grpc.StreamServerInterceptor].
// Ensure to configure the [Interceptor] with the required checks.
// If no checks are provided the interceptor will allow public access to the API.
func (i *Interceptor[T]) Stream() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := i.intercept(stream.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return handler(srv, &serverStream{ServerStream: stream, ctx: ctx})
	}
}

// Context wraps the [authorization.Context] function to directly return the typed [authorization.Ctx] of the [Interceptor].
func (i *Interceptor[T]) Context(ctx context.Context) T {
	return authorization.Context[T](ctx)
}

func (i *Interceptor[T]) intercept(ctx context.Context, method string) (context.Context, error) {
	for endpoint, checks := range i.checks {
		if endpoint != method {
			continue
		}
		authCtx, err := i.authorizer.CheckAuthorization(ctx, metautils.ExtractIncoming(ctx).Get(authorization.HeaderName), checks...)
		if err != nil {
			if errors.Is(err, &authorization.UnauthorizedErr{}) {
				return nil, status.Error(codes.Unauthenticated, err.Error())
			}
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
		return authorization.WithAuthContext(ctx, authCtx), nil
	}
	return ctx, nil
}

// serverStream is required to be able to intercept and annotate the [context.Context]
// between the client call and the server.
type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *serverStream) Context() context.Context {
	return s.ctx
}
