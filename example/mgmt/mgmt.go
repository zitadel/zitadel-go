package main

import (
	"context"
	"flag"
	"log"

	"github.com/caos/oidc/pkg/oidc"

	"github.com/caos/zitadel-go/pkg/client/management"
	"github.com/caos/zitadel-go/pkg/client/middleware"
	"github.com/caos/zitadel-go/pkg/client/zitadel"
	pb "github.com/caos/zitadel-go/pkg/client/zitadel/management"
)

var (
	orgID = flag.String("orgID", "74161146763996133", "orgID to set for overwrite example (default is ACME on zitadel.ch)")
)

func main() {
	flag.Parse()

	//create a client for the management api providing:
	//- scopes (including the ZITADEL project ID),
	//- a JWT Profile token source (e.g. path to your key json), if not provided, the file will be read from the path set in env var ZITADEL_KEY_PATH
	//- id of the organisation where your calls will be executed
	//(default is the resource owner / organisation of the calling user, can also be provided for every call separately)
	client, err := management.NewClient(
		[]string{oidc.ScopeOpenID, zitadel.ScopeZitadelAPI()},
		//zitadel.WithJWTProfileTokenSource(middleware.JWTProfileFromPath("key.json")),
		//zitadel.WithOrgID(*orgID),
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
	//for this example just set the `orgID` flag
	respOverwrite, err := client.GetMyOrg(middleware.SetOrgID(ctx, *orgID), &pb.GetMyOrgRequest{})
	if err != nil {
		log.Fatalln("call failed: ", err)
	}
	log.Printf("%s was created on: %s", respOverwrite.Org.Name, respOverwrite.Org.Details.CreationDate.AsTime())
}
