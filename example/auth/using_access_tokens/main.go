package main

import (
	"context"
	"flag"
	"log"
	"os"

	"golang.org/x/exp/slog"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	domain = flag.String("domain", "", "your ZITADEL instance domain")
	token  = flag.String("token", "", "your personal access token")
)

func main() {
	flag.Parse()
	ctx := context.Background()

	authOption := client.PAT(*token)

	api, err := client.New(ctx, zitadel.New(*domain), client.WithAuth(authOption))
	if err != nil {
		slog.Error("could not create api client", "error", err)
		os.Exit(1)
	}

	resp, err := api.ManagementService().GetMyOrg(ctx, &management.GetMyOrgRequest{})
	if err != nil {
		slog.Error("gRPC call failed", "error", err)
		os.Exit(1)
	}

	log.Printf("Successfully called API: Your organization is %s", resp.GetOrg().GetName())
}
