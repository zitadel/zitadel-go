package main

import (
	"context"
	"flag"
	"os"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/exp/slog"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	// flags to be provided for running the example server
	domain  = flag.String("domain", "", "your ZITADEL instance domain (in the form: <instance>.zitadel.cloud or <yourdomain>)")
	keyPath = flag.String("key", "", "path to your key.json")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	// Initiate the API client by providing at least a zitadel configuration.
	// You can also directly set an authorization option, resp. provide its authentication mechanism,
	// by passing the downloaded service user key:
	api, err := client.New(ctx, zitadel.New(*domain),
		client.WithAuth(client.DefaultServiceUserAuthentication(*keyPath, oidc.ScopeOpenID, client.ScopeZitadelAPI())),
	)

	resp, err := api.ManagementService().GetMyOrg(ctx, &management.GetMyOrgRequest{})
	if err != nil {
		slog.Error("cannot retrieve the organisation", "error", err)
		os.Exit(1)
	}
	slog.Info("retrieved the organisation", "orgID", resp.GetOrg().GetId(), "name", resp.GetOrg().GetName())
}
