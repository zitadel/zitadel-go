package client_test

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

// ExampleClient_GetValidToken demonstrates how to retrieve a valid access token
// from the client for making custom API calls to endpoints not covered by the SDK.
func ExampleClient_GetValidToken() {
	ctx := context.Background()

	// Create a client with JWT profile authentication
	authOption := client.DefaultServiceUserAuthentication(
		"path/to/key.json",
		oidc.ScopeOpenID,
		client.ScopeZitadelAPI(),
	)

	api, err := client.New(ctx, zitadel.New("example.zitadel.cloud"), client.WithAuth(authOption))
	if err != nil {
		log.Fatal(err)
	}
	defer api.Close()

	// Get a valid token for custom API calls
	token, err := api.GetValidToken()
	if err != nil {
		log.Fatal(err)
	}

	// Use the token for custom HTTP requests to ZITADEL endpoints
	// not covered by the SDK
	req, _ := http.NewRequest("GET", "https://example.zitadel.cloud/custom/endpoint", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	// The token will be automatically refreshed by the SDK if expired
	fmt.Printf("Token retrieved successfully (length: %d)\n", len(token))
}
