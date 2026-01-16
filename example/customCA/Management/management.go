package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel-go/v3/example/customCA/middleware"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/credentials"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	caFile  = flag.String("caFile", "", "The CA file")
	keyFile = flag.String("keyFile", "", "The JWT Profile key file")
	domain  = flag.String("domain", "", "domain of your ZITADEL instance (in the form: <instance>.zitadel.cloud or <yourdomain>)")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	// build tls config with custom CA
	var tlsConfig = &tls.Config{}
	if *caFile != "" {
		certPool := x509.NewCertPool()
		bs, err := os.ReadFile(*caFile)
		if err != nil {
			log.Fatalf("failed to read cert.pem: %s", err)
		}
		ok := certPool.AppendCertsFromPEM(bs)
		if !ok {
			log.Fatalf("failed to append certs")
		}
		tlsConfig.RootCAs = certPool
	}
	// create http client with custom tls config
	hClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	// create jwt profile middleware from key file and http client
	mw := middleware.JWTProfileFromFile(ctx, *keyFile, hClient)
	authOption := client.WithAuth(func(ctx context.Context, issuer string) (oauth2.TokenSource, error) {

		return mw(issuer, []string{oidc.ScopeOpenID, client.ScopeZitadelAPI()})
	})
	// create zitadel api client with custom http client middleware and grpc transport credentials
	api, err := client.New(ctx, zitadel.New(*domain), authOption, client.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
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

	resp2, err := api.ManagementService().ListOrgMembers(ctx, &management.ListOrgMembersRequest{})
	if err != nil {
		slog.Error("gRPC call failed", "error", err)
		os.Exit(1)
	}

	for _, m := range resp2.Result {
		log.Printf("Successfully called API: Member is %s", m.DisplayName)

	}
}
