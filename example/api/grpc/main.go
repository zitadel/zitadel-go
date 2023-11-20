package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	v3alpha "github.com/zitadel/zitadel-go/v2/example/api/grpc/proto"
	"github.com/zitadel/zitadel-go/v2/pkg/authorization/oauth"
	"github.com/zitadel/zitadel-go/v2/pkg/grpc/middleware"
	"github.com/zitadel/zitadel-go/v2/pkg/zitadel"
)

var (
	domain = flag.String("domain", "", "your ZITADEL instance domain (in the form: https://<instance>.zitadel.cloud or https://<yourdomain>)")
	key    = flag.String("key", "", "path to your key.json")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	z, err := zitadel.New(*domain,
		zitadel.WithAuthorization(ctx,
			oauth.DefaultAuthorization(*key),
		),
	)
	if err != nil {
		slog.Error("zitadel sdk could not initialize", "error", err)
		os.Exit(1)
	}

	// Initialize the GRPC middleware by providing the sdk and the authorization checks
	mw := middleware.New(z.Authorization, checks)

	// Create the GRPC server and provide the necessary interceptors
	serverOptions := []grpc.ServerOption{
		grpc.UnaryInterceptor(mw.Unary()),
		grpc.StreamInterceptor(mw.Stream()),
	}
	grpcServer := grpc.NewServer(serverOptions...)

	// Register your server implementation
	v3alpha.RegisterExampleServiceServer(grpcServer, &Server[*oauth.IntrospectionContext]{})
	// for easier use, we also register the grpc server reflection
	reflection.Register(grpcServer)

	// finally start the server on port 8099
	lis, err := net.Listen("tcp", ":8089")
	if err != nil {
		slog.Error("creating listener failed", "error", err)
		os.Exit(1)
	}
	err = grpcServer.Serve(lis)
	if err != nil {
		slog.Error("server terminated", "error", err)
		os.Exit(1)
	}
}
