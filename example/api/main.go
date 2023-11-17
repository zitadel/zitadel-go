package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/zitadel/zitadel-go/v2/pkg/authorization"
	"github.com/zitadel/zitadel-go/v2/pkg/authorization/oauth"
	"github.com/zitadel/zitadel-go/v2/pkg/http/middleware"
	"github.com/zitadel/zitadel-go/v2/pkg/zitadel"
)

/*
 This example demonstrates how to secure an HTTP API with ZITADEL using the provided authorization (AuthZ) middleware.

 It will serve the following 3 different endpoints:
 - /api/public (can be called by anyone)
 - /api/protected (requires authorization)
 - /api/protected-admin (requires authorization with granted `admin` role)
*/

func main() {

	ctx := context.Background()

	// Initiate the zitadel sdk by providing its domain
	// and as this example will focus on authorization (using Oauth2 Introspection),
	// you will also need to initialize that with the downloaded api key.json
	//
	// it's a short form of:
	// 	z, err := zitadel.New("https://livio-rodepo.zitadel.cloud",
	//		zitadel.WithAuthorization(ctx,
	//			oauth.WithIntrospection[*oauth.IntrospectionContext](
	//				oauth.JWTProfileIntrospectionAuthentication("./240991537406674288.json"),
	//			),
	//		),
	//	)
	z, err := zitadel.New("https://livio-rodepo.zitadel.cloud",
		zitadel.WithAuthorization(ctx,
			oauth.DefaultAuthorization("./240991537406674288.json"),
		),
	)
	if err != nil {
		slog.Error("zitadel sdk could not initialize", "error", err)
		os.Exit(1)
	}

	// Initialize the HTTP middleware by providing the sdk
	mw := middleware.New(z.Authorization)

	router := http.NewServeMux()

	// This endpoint is accessible by anyone.
	router.Handle("/api/public", printContext())

	// This endpoint is only accessible with a valid authorization (in this case a valid access_token).
	router.Handle("/api/protected", mw.RequireAuthorization()(printContext()))

	// This endpoint is only accessible with a valid authorization, which was granted the `admin` role.
	router.Handle("/api/protected-admin", mw.RequireAuthorization(authorization.WithRole(`admin`))(printContext()))

	lis := ":8089"
	slog.Info("server listening, press ctrl+c to stop", "addr", "http://localhost"+lis)
	err = http.ListenAndServe(lis, router)
	if !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server terminated", "error", err)
		os.Exit(1)
	}
}

// printContext is used in this example to demonstrate how to get additional information from the [authorization.Context]
// and use it in your handler / implementation.
//
// For simplicity the function will only return those infos, but in an actual implementation, you could use it to:
// - do additional checks / restrictions
// - extract the authorized user and its attributes
// - ...
func printContext() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		authCtx := authorization.Context(req.Context())
		data, err := json.Marshal(&struct {
			Now        time.Time         `json:"now,omitempty"`
			Authorized bool              `json:"authorized,omitempty"`
			User       bool              `json:"user,omitempty"`
			UserInOrg  bool              `json:"user_in_org,omitempty"`
			Ctx        authorization.Ctx `json:"ctx,omitempty"`
		}{
			Now:        time.Now(),
			Authorized: authCtx.IsAuthorized(),
			User:       authCtx.IsGrantedRole("user"),
			UserInOrg:  authCtx.IsGrantedRoleForOrganization("user", "hodor"),
			Ctx:        authCtx,
		})
		if err != nil {
			slog.Error("error marshalling response data", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(data)
		if err != nil {
			slog.Error("error writing response", "error", err)
		}
	}
}
