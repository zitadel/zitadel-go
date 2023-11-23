package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/zitadel/zitadel-go/v2/pkg/authorization"
	"github.com/zitadel/zitadel-go/v2/pkg/authorization/oauth"
	"github.com/zitadel/zitadel-go/v2/pkg/http/middleware"
	"github.com/zitadel/zitadel-go/v2/pkg/zitadel"
)

var (
	domain = flag.String("domain", "", "your ZITADEL instance domain (in the form: https://<instance>.zitadel.cloud or https://<yourdomain>)")
	key    = flag.String("key", "", "path to your key.json")
	tasks  []string
)

/*
 This example demonstrates how to secure an HTTP API with ZITADEL using the provided authorization (AuthZ) middleware.

 It will serve the following 3 different endpoints:
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
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err = w.Write([]byte(`"OK"`))
			if err != nil {
				slog.Error("error writing response", "error", err)
			}
		}))

	// This endpoint is only accessible with a valid authorization (in this case a valid access_token / PAT).
	router.Handle("/api/tasks", mw.RequireAuthorization()(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// Using the [authorization.Context] function we can gather information about the authorized user.
			// This example will just print the users ID using the provided method, and it will also
			// print the username by directly access the field of the typed [*oauth.IntrospectionContext].
			authCtx := authorization.Context[*oauth.IntrospectionContext](r.Context())
			slog.Info("user accessed task list", "id", authCtx.UserID(), "username", authCtx.Username)

			// Although this endpoint is accessible by any authorized user, you might want to take additional steps
			// if the user is granted a specific role. In this case an `admin` will be informed to add a new task:
			taskList := tasks
			if authCtx.IsGrantedRole("admin") {
				taskList = append(taskList, "create a new task on /api/add-task")
			}

			// return the existing task list
			data, err := json.Marshal(taskList)
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err = w.Write(data)
			if err != nil {
				slog.Error("error writing response", "error", err)
			}
		})))

	// This endpoint is only accessible with a valid authorization, which was granted the `admin` role (in any organization).
	router.Handle("/api/add-task", mw.RequireAuthorization(authorization.WithRole(`admin`))(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			task := strings.TrimSpace(r.FormValue("task"))
			if task == "" {
				http.Error(w, "task must not be empty", http.StatusBadRequest)
				return
			}
			tasks = append(tasks, task)

			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err = w.Write([]byte(fmt.Sprintf(`"task %v added"`, task)))
			if err != nil {
				slog.Error("error task added response", "error", err)
			}
			// since we only want the authorized userID and don't need any specific data, we can simply use [authorization.UserID]
			slog.Info("admin added task", "id", authorization.UserID(r.Context()), "task", task)
		})))

	// start the server on http://localhost:8089
	lis := ":8089"
	slog.Info("server listening, press ctrl+c to stop", "addr", "http://localhost"+lis)
	err = http.ListenAndServe(lis, router)
	if !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server terminated", "error", err)
		os.Exit(1)
	}
}
