package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"golang.org/x/exp/slog"

	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
	"github.com/zitadel/zitadel-go/v3/pkg/authorization/oauth"
	"github.com/zitadel/zitadel-go/v3/pkg/http/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	// flags to be provided for running the example server
	domain = flag.String("domain", "", "your ZITADEL instance domain (in the form: https://<instance>.zitadel.cloud or https://<yourdomain>)")
	key    = flag.String("key", "", "path to your key.json")
	port   = flag.String("port", "8089", "port to run the server on (default is 8089)")

	// tasks are used to store an in-memory list used in the protected endpoint
	tasks []string
)

/*
 This example demonstrates how to secure an HTTP API with ZITADEL using the provided authorization (AuthZ) middleware.

 It will serve the following 3 different endpoints:
 (These are meant to demonstrate the possibilities and do not follow REST best practices):

- /api/healthz (can be called by anyone)
 - /api/tasks (requires authorization)
 - /api/add-task (requires authorization with granted `admin` role)
*/

func main() {
	flag.Parse()

	ctx := context.Background()

	// Initiate the zitadel sdk by providing its domain
	// and as this example will focus on authorization (using Oauth2 Introspection),
	// you will also need to initialize that with the downloaded api key.json
	//
	// it's a short form of:
	// 	z, err := zitadel.New("https://your-domain.zitadel.cloud",
	//		zitadel.WithAuthorization(ctx,
	//			oauth.WithIntrospection[*oauth.IntrospectionContext](
	//				oauth.JWTProfileIntrospectionAuthentication("./key.json"),
	//			),
	//		),
	//	)
	z, err := zitadel.New(*domain,
		zitadel.WithAuthorization(ctx,
			oauth.DefaultAuthorization(*key),
		),
	)
	if err != nil {
		slog.Error("zitadel sdk could not initialize", "error", err)
		os.Exit(1)
	}

	// Initialize the HTTP middleware by providing the sdk
	mw := middleware.New(z.Authorization)

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
	// It will list all stored tasks. In case the user is granted the `admin` role it will add a separate task telling him
	// to add a new task.
	router.Handle("/api/tasks", mw.RequireAuthorization()(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// Using the [middleware.Context] function we can gather information about the authorized user.
			// This example will just print the users ID using the provided method, and it will also
			// print the username by directly access the field of the typed [*oauth.IntrospectionContext].
			authCtx := mw.Context(r.Context())
			slog.Info("user accessed task list", "id", authCtx.UserID(), "username", authCtx.Username)

			// Although this endpoint is accessible by any authorized user, you might want to take additional steps
			// if the user is granted a specific role. In this case an `admin` will be informed to add a new task:
			list := tasks
			if authCtx.IsGrantedRole("admin") {
				list = append(list, "create a new task on /api/add-task")
			}

			// return the existing task list
			err = jsonResponse(w, &taskList{Tasks: list}, http.StatusOK)
			if err != nil {
				slog.Error("error writing response", "error", err)
			}
		})))

	// This endpoint is only accessible with a valid authorization, which was granted the `admin` role (in any organization).
	// It will add the provided task to the list of existing ones.
	router.Handle("/api/add-task", mw.RequireAuthorization(authorization.WithRole(`admin`))(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// get the provided task and do not accept an empty value
			task := strings.TrimSpace(r.FormValue("task"))
			if task == "" {
				err = jsonResponse(w, "task must not be empty", http.StatusBadRequest)
				if err != nil {
					slog.Error("error writing invalid task response", "error", err)
					return
				}
				return
			}

			// since it was not empty, let's add it to the existing list
			tasks = append(tasks, task)

			// since we only want the authorized userID and don't need any specific data, we can simply use [authorization.UserID]
			slog.Info("admin added task", "id", authorization.UserID(r.Context()), "task", task)

			// inform the admin about the successful addition
			err = jsonResponse(w, fmt.Sprintf("task `%s` added", task), http.StatusOK)
			if err != nil {
				slog.Error("error writing task added response", "error", err)
				return
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

type taskList struct {
	Tasks []string `json:"tasks,omitempty"`
}
