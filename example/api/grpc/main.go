package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"

	"golang.org/x/exp/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	v3alpha "github.com/zitadel/zitadel-go/v3/example/api/grpc/proto"
	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
	"github.com/zitadel/zitadel-go/v3/pkg/authorization/oauth"
	"github.com/zitadel/zitadel-go/v3/pkg/grpc/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	// flags to be provided for running the example server
	domain = flag.String("domain", "", "your ZITADEL instance domain (in the form: <instance>.zitadel.cloud or <yourdomain>)")
	key    = flag.String("key", "", "path to your key.json")
	port   = flag.String("port", "8089", "port to run the server on (default is 8089)")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	// Initiate the authorization by providing a zitadel configuration and a verifier.
	// This example will use OAuth2 Introspection for this, therefore you will also need to provide the downloaded api key.json
	authZ, err := authorization.New(ctx, zitadel.New(*domain), oauth.DefaultAuthorization(*key))
	if err != nil {
		slog.Error("zitadel sdk could not initialize", "error", err)
		os.Exit(1)
	}

	// Initialize the GRPC middleware by providing the sdk and the authorization checks
	mw := middleware.New(authZ, checks)

	// Create the GRPC server and provide the necessary interceptors
	serverOptions := []grpc.ServerOption{
		grpc.UnaryInterceptor(mw.Unary()),
		grpc.StreamInterceptor(mw.Stream()),
	}
	grpcServer := grpc.NewServer(serverOptions...)

	// Register your server implementation
	v3alpha.RegisterExampleServiceServer(grpcServer, NewServer(mw))
	// for easier use, we also register the grpc server reflection
	reflection.Register(grpcServer)

	// finally start the server on port 8099
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", *port))
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
