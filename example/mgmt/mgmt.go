package main

import (
	"context"
	"log"

	"github.com/caos/oidc/pkg/oidc"

	"github.com/caos/zitadel-go/pkg/client/management"
	"github.com/caos/zitadel-go/pkg/client/middleware"
	"github.com/caos/zitadel-go/pkg/client/zitadel"
	pb "github.com/caos/zitadel-go/pkg/client/zitadel/management"
)

func main() {
	//create a client for the management api providing:
	//- scopes (including the ZITADEL project ID),
	//- path to your key json (if not provided by environment variable)
	//- id of the organisation where your calls will be executed (can also be provided for every call separately)
	client, err := management.NewClient(
		[]string{oidc.ScopeOpenID, zitadel.ScopeZitadelAPI()},
		zitadel.WithKeyPath("./key.json"),
		zitadel.WithOrgID("74161146763996133"),
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

	ctx := context.Background()

	//call ZITADEL and print the name and creation date of your organisation
	//the call was successful if no error occurred
	resp, err := client.GetMyOrg(ctx, &pb.GetMyOrgRequest{})
	if err != nil {
		log.Fatalln("call failed: ", err)
	}
	log.Printf("%s was created on: %s", resp.Org.Name, resp.Org.Details.CreationDate.AsTime())

	//if you need an other organisation context for some call, you can overwrite it by setting the orgID directly
	respOverwrite, err := client.GetMyOrg(middleware.SetOrgID(ctx, "103000304424903098"), &pb.GetMyOrgRequest{})
	if err != nil {
		log.Fatalln("call failed: ", err)
	}
	log.Printf("%s was created on: %s", respOverwrite.Org.Name, respOverwrite.Org.Details.CreationDate.AsTime())
}