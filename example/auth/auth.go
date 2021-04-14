package main

import (
	"context"
	"log"

	"github.com/caos/oidc/pkg/oidc"

	"github.com/caos/zitadel-go/pkg/client/auth"
	"github.com/caos/zitadel-go/pkg/client/zitadel"
	pb "github.com/caos/zitadel-go/pkg/client/zitadel/auth"
)

func main() {
	//create a client for the auth api providing:
	//- scopes (including the ZITADEL project ID),
	//- path to your key json (if not provided by environment variable)
	client, err := auth.NewClient(
		[]string{oidc.ScopeOpenID, zitadel.ScopeZitadelAPI()},
		zitadel.WithKeyPath("./key.json"),
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

	//call ZITADEL and print the name and creation date of your service user
	//the call was successful if no error occurred
	resp, err := client.GetMyUser(ctx, &pb.GetMyUserRequest{})
	if err != nil {
		log.Fatalln("call failed: ", err)
	}
	log.Printf("%s was created on %s", resp.User.UserName, resp.User.Details.CreationDate.AsTime())
}
