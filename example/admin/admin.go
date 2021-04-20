package main

import (
	"context"
	"log"

	"github.com/caos/oidc/pkg/oidc"

	"github.com/caos/zitadel-go/pkg/client/admin"
	"github.com/caos/zitadel-go/pkg/client/zitadel"
	pb "github.com/caos/zitadel-go/pkg/client/zitadel/admin"
)

func main() {
	//create a client for the admin api providing:
	//- scopes (including the ZITADEL project ID),
	//- path to your key json (if not provided by environment variable)
	client, err := admin.NewClient(
		[]string{oidc.ScopeOpenID, zitadel.ScopeZitadelAPI()},
		zitadel.WithKeyPath("key.json"),
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
	//call ZITADEL and print the name and creation date of the requested organisation
	//the call was successful if no error occurred
	resp, err := client.GetOrgByID(ctx, &pb.GetOrgByIDRequest{
		Id: "74161146763996133",
	})
	if err != nil {
		log.Fatalln("call failed: ", err)
	}
	log.Printf("%s was created on %s", resp.Org.Name, resp.Org.Details.CreationDate.AsTime())
}
