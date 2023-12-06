package main

import (
	"context"
	"flag"
	"log"

	"github.com/zitadel/zitadel-go/v3/pkg/client/system"
	pb "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/system"
)

var (
	issuer = flag.String("issuer", "", "issuer of your ZITADEL instance (in the form: https://<instance>.zitadel.cloud or https://<yourdomain>)")
	api    = flag.String("api", "", "gRPC endpoint of your ZITADEL instance (in the form: <instance>.zitadel.cloud:443 or <yourdomain>:443)")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	//create a client for the system api providing:
	//- issuer (e.g. https://acme-dtfhdg.zitadel.cloud)
	//- api (e.g. acme-dtfhdg.zitadel.cloud:443)
	//- a JWT Profile source token (e.g. path to your key.pem) and the corresponding userID from the `SystemAPIUsers` config in ZITADEL
	client, err := system.NewClient(
		ctx,
		*issuer,
		*api,
		system.JWTProfileFromPath("system_user_1.pem", "system_user_1"),
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

	//call ZITADEL and print the name and creation date of all instances
	//the call was successful if no error occurred
	resp, err := client.ListInstances(ctx, &pb.ListInstancesRequest{})
	if err != nil {
		log.Fatalln("call failed: ", err)
	}
	//print all instances
	for _, instance := range resp.GetResult() {
		log.Printf("%s was created on %s", instance.Name, instance.Details.CreationDate.AsTime())
	}
}
