package main

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	v3alpha "github.com/zitadel/zitadel-go/v2/example/api/grpc/proto"
	"github.com/zitadel/zitadel-go/v2/pkg/authorization"
	"github.com/zitadel/zitadel-go/v2/pkg/authorization/oauth"
)

var _ v3alpha.ExampleServiceServer = (*Server[*oauth.IntrospectionContext])(nil)

var (
	checks = map[string][]authorization.CheckOption{
		v3alpha.ExampleService_Protected_FullMethodName:          nil,
		v3alpha.ExampleService_ProtectedAdmin_FullMethodName:     {authorization.WithRole("admin")},
		v3alpha.ExampleService_ClientStream_FullMethodName:       nil,
		v3alpha.ExampleService_ServerStream_FullMethodName:       nil,
		v3alpha.ExampleService_ClientServerStream_FullMethodName: nil,
	}
)

type Server[T authorization.Ctx] struct {
	v3alpha.UnimplementedExampleServiceServer
}

func (s *Server[T]) Public(ctx context.Context, request *v3alpha.PublicRequest) (*v3alpha.PublicResponse, error) {
	respCtx, err := ctxToStructPb[T](ctx)
	if err != nil {
		return nil, err
	}
	return &v3alpha.PublicResponse{
		Context: respCtx,
	}, nil
}

func (s *Server[T]) Protected(ctx context.Context, request *v3alpha.ProtectedRequest) (*v3alpha.ProtectedResponse, error) {
	respCtx, err := ctxToStructPb[T](ctx)
	if err != nil {
		return nil, err
	}
	return &v3alpha.ProtectedResponse{
		Context: respCtx,
	}, nil
}

func (s *Server[T]) ProtectedAdmin(ctx context.Context, request *v3alpha.ProtectedAdminRequest) (*v3alpha.ProtectedAdminResponse, error) {
	respCtx, err := ctxToStructPb[T](ctx)
	if err != nil {
		return nil, err
	}
	return &v3alpha.ProtectedAdminResponse{
		Context: respCtx,
	}, nil
}

func (s *Server[T]) ClientServerStream(stream v3alpha.ExampleService_ClientServerStreamServer) error {
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		ctx, err := ctxToStructPb[T](stream.Context())
		if err != nil {
			return err
		}
		err = stream.Send(&v3alpha.ClientServerStreamResponse{Context: ctx})
		if err != nil {
			return err
		}
	}
}

func (s *Server[T]) ServerStream(request *v3alpha.ServerStreamRequest, stream v3alpha.ExampleService_ServerStreamServer) error {
	for i := 0; i < 3; i++ {
		ctx, err := ctxToStructPb[T](stream.Context())
		if err != nil {
			return err
		}
		if err = stream.Send(&v3alpha.ServerStreamResponse{Context: ctx}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server[T]) ClientStream(stream v3alpha.ExampleService_ClientStreamServer) error {
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			ctx, err := ctxToStructPb[T](stream.Context())
			if err != nil {
				return err
			}
			return stream.SendAndClose(&v3alpha.ClientStreamResponse{Context: ctx})
		}
		if err != nil {
			return err
		}
	}
}

func ctxToStructPb[T authorization.Ctx](ctx context.Context) (*structpb.Struct, error) {
	authCtx := authorization.Context[T](ctx)

	a, _ := json.Marshal(authCtx)
	return structpb.NewStruct(map[string]interface{}{
		"now": time.Now().String(),
		"ctx": string(a),
	})
}
