package zitadel_test

import (
	"context"
	"log"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/management"
	"github.com/zitadel/zitadel-go/v3/pkg/client/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
)

// ExampleWithJWTProfileTokenSourceContext demonstrates how to apply the transport headers and the TLS options
// of a direct client to the OIDC discovery and token requests of the JWT profile authentication as well.
func ExampleWithJWTProfileTokenSourceContext() {
	ctx := context.Background()

	api, err := management.NewClient(
		ctx,
		"https://zitadel.internal.example",
		"zitadel.internal.example:443",
		[]string{oidc.ScopeOpenID, client.ScopeZitadelAPI()},
		zitadel.WithTransportHeader("Proxy-Authorization", "Bearer <proxy token>"),
		zitadel.WithJWTProfileTokenSourceContext(middleware.JWTProfileFromPathContext("path/to/key.json")),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = api.Connection.Close()
	}()
}
