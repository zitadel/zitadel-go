package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel-go/v3/example/customCA/middleware"
	client2 "github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/admin"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
	pb "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/admin"
	"google.golang.org/grpc/credentials"
)

var (
	caFile  = flag.String("caFile", "", "The CA file")
	keyFile = flag.String("keyFile", "", "The JWT Profile key file")
	issuer  = flag.String("issuer", "", "issuer of your ZITADEL instance (in the form: https://<instance>.zitadel.cloud or https://<yourdomain>)")
	api     = flag.String("api", "", "gRPC endpoint of your ZITADEL instance (in the form: <instance>.zitadel.cloud:443 or <yourdomain>:443)")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	//build tls config with custom CA
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
	//create http client with custom tls config
	hClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	//create a client for the admin api providing:
	//- issuer (e.g. https://acme-dtfhdg.zitadel.cloud)
	//- api (e.g. acme-dtfhdg.zitadel.cloud:443)
	//- scopes (including the ZITADEL project ID),
	//- a JWT Profile source token (e.g. path to your key json), if not provided, the file will be read from the path set in env var ZITADEL_KEY_PATH
	client, err := admin.NewClient(
		ctx,
		*issuer,
		*api,
		[]string{oidc.ScopeOpenID, client2.ScopeZitadelAPI()},
		//provide the jwt profile token source middleware with the key file and the custom http client
		zitadel.WithJWTProfileTokenSource(middleware.JWTProfileFromFileWithHTTP(ctx, *keyFile, hClient)),
		//provide the grpc transport credentials with the custom tls config
		zitadel.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	if err != nil {
		log.Fatalln("could not create client", err)
	}
	defer func() {
		err := client.Connection.Close()
		if err != nil {
			log.Println("could not close grpc connection", err)
		}
	}()

	//call ZITADEL and print the name and creation date of the requested organisation
	//the call was successful if no error occurred
	resp, err := client.ListOrgs(ctx, &pb.ListOrgsRequest{})
	if err != nil {
		log.Fatalln("call failed: ", err)
	}

	for _, org := range resp.Result {
		log.Printf("%s - %v - was created on %s", org.Name, org.GetId(), org.Details.CreationDate.AsTime())
	}

}
