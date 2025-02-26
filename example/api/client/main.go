package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/exp/slog"

	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
	"github.com/zitadel/zitadel-go/v3/pkg/authorization/oauth"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/auth"
	"github.com/zitadel/zitadel-go/v3/pkg/http/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	// flags to be provided for running the example server
	domain = flag.String("domain", "", "your ZITADEL instance domain (in the form: <instance>.zitadel.cloud or <yourdomain>)")
	key    = flag.String("key", "", "path to your api key.json")
	port   = flag.String("port", "8089", "port to run the server on (default is 8089)")
)

/*
 This example demonstrates how to secure an HTTP API with ZITADEL using the provided authorization (AuthZ) middleware
 in combination with using the ZITADEL API as well.

 It will serve the following 2 different endpoints:
 (These are meant to demonstrate the possibilities and do not follow REST best practices):

 - /api/healthz (can be called by anyone)
 - /api/permissions (requires authorization)
*/

func main() {
	flag.Parse()

	ctx := context.Background()

	// Initiate the zitadel sdk by providing its domain
	// and as this example will focus on authorization (using OAuth2 Introspection),
	// you will also need to initialize that with the downloaded api key.json

	conf := zitadel.New(*domain)
	authZ, err := authorization.New(ctx, conf, oauth.DefaultAuthorization(*key))
	if err != nil {
		slog.Error("zitadel sdk could not initialize authorization", "error", err)
		os.Exit(1)
	}
	// Initialize the HTTP middleware by providing the sdk
	mw := middleware.New(authZ)

	// as we will also call the ZITADEL API, we need to initialize the client
	c, err := client.New(ctx, conf)
	if err != nil {
		slog.Error("zitadel sdk could not initialize authorization", "error", err)
		os.Exit(1)
	}

	router := http.NewServeMux()

	// This endpoint is accessible by anyone and will always return "200 OK" to indicate the API is running
	router.Handle("/api/healthz", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			err = jsonResponse(w, "OK", http.StatusOK)
			if err != nil {
				slog.Error("error writing response", "error", err)
			}
		}))

	// This endpoint is only accessible with a valid authorization (in this case a valid access_token / PAT).
	// It will call ZITADEL to additionally get all permissions granted to the user in ZITADEL and return that.
	router.Handle("/api/permissions", mw.RequireAuthorization()(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// Using the [middleware.Context] function we can gather information about the authorized user.
			// This example will just print the users ID using the provided method, and it will also
			// print the username by directly access the field of the typed [*oauth.IntrospectionContext].
			authCtx := mw.Context(r.Context())
			slog.Info("user accessed permission check", "id", authCtx.UserID(), "username", authCtx.Username)

			// we use the callers on token to retrieve the permission on the ZITADEL API
			// this will only work if ZITADEL is contained in the tokens audience (e.g. a PAT will always do so)
			resp, err := c.AuthService().ListMyZitadelPermissions(client.AuthorizedUserCtx(r.Context()), &auth.ListMyZitadelPermissionsRequest{})
			if err != nil {
				slog.Error("error listing zitadel permissions", "error", err)
				return
			}

			err = jsonResponse(w, resp.Result, http.StatusOK)
			if err != nil {
				slog.Error("error writing response", "error", err)
			}
		})))

	// start the server on the specified port (default http://localhost:8089)
	lis := fmt.Sprintf(":%s", *port)
	slog.Info("server listening, press ctrl+c to stop", "addr", "http://localhost"+lis)
	err = http.ListenAndServe(lis, router)
	if !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server terminated", "error", err)
		os.Exit(1)
	}
}

// jsonResponse is a simple helper function to return a proper JSON response
func jsonResponse(w http.ResponseWriter, resp any, status int) error {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
