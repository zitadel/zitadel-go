package main

import (
	"context"
	"log"
	"net"

	"github.com/caos/zitadel-go/example/grpc/proto"
	api_mw "github.com/caos/zitadel-go/pkg/api/middleware"
	grpc_mw "github.com/caos/zitadel-go/pkg/api/middleware/grpc"
	"github.com/caos/zitadel-go/pkg/client"
	"github.com/caos/zitadel-go/pkg/client/middleware"
	"google.golang.org/grpc"
)

func main() {
	introspection, err := grpc_mw.NewIntrospectionInterceptor(client.Issuer, middleware.OSKeyPath(),
		grpc_mw.WithIgnoredPaths("/zitadel.go.example.Example/Public"),
		grpc_mw.WithIntrospectionOptions(api_mw.WithCheckClaim("test", "test")),
	)
	if err != nil {
		log.Fatalln(err)
	}
	server := grpc.NewServer(
		grpc.UnaryInterceptor(introspection.Unary()),
	)
	proto.RegisterExampleServer(server, &Server{})
	listener, err := net.Listen("tcp", ":5001")
	if err != nil {
		log.Fatalln(err)
	}
	server.Serve(listener)
}

type Server struct {
	proto.UnimplementedExampleServer
}

func (s *Server) Public(ctx context.Context, _ *proto.PublicRequest) (*proto.PublicResponse, error) {
	return &proto.PublicResponse{Ok: "op"}, nil
}

func (s *Server) Protected(ctx context.Context, _ *proto.ProtectedRequest) (*proto.ProtectedResponse, error) {
	return &proto.ProtectedResponse{Ok: "op"}, nil
}
