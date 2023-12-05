package main

import (
	"context"
	"embed"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"

	http2 "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/authentication"
	openid "github.com/zitadel/zitadel-go/v3/pkg/authentication/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	// flags to be provided for running the example server
	domain   = flag.String("domain", "", "your ZITADEL instance domain (in the form: https://<instance>.zitadel.cloud or https://<yourdomain>)")
	key      = flag.String("key", "", "path to your key.json")
	clientID = flag.String("clientID", "", "clientID provided by ZITADEL")
	port     = flag.String("port", "8089", "port to run the server on (default is 8089)")

	//go:embed "templates/*.html"
	templates embed.FS

	// tasks are used to store an in-memory list used in the protected endpoint
	tasks []string
)

func main() {
	flag.Parse()

	ctx := context.Background()

	t, err := template.New("").ParseFS(templates, "templates/*.html")
	if err != nil {
		slog.Error("unable to parse template", "error", err)
		os.Exit(1)
	}

	// Initiate the zitadel sdk by providing its domain
	// and as this example will focus on authentication (using OIDC / OAuth2 PKCE flow),
	// you will also need to initialize that with the generated client_id.
	//
	// it's a short form of:
	// 	z, err := zitadel.New("https://your-domain.zitadel.cloud",
	//		zitadel.WithAuthorization(ctx,
	//			oauth.WithIntrospection[*oauth.IntrospectionContext](
	//				oauth.JWTProfileIntrospectionAuthentication("./key.json"),
	//			),
	//		),
	//	)
	key := []byte("XKv2Lqd7YAq13NUZVUWZEWZeruqyzViM")
	cookieHandler := http2.NewCookieHandler(key, key)
	z, err := zitadel.New(*domain,
		zitadel.WithAuthentication(ctx,
			openid.WithCodeFlow[*openid.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo], *oidc.IDTokenClaims, *oidc.UserInfo](
				openid.PKCEAuthentication(*clientID, "http://localhost:8089/callback", []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail}, cookieHandler),
			),
		),
	)

	if err != nil {
		slog.Error("zitadel sdk could not initialize", "error", err)
		os.Exit(1)
	}

	mw := authentication.Middleware(z.Authentication)

	router := http.NewServeMux()

	router.Handle("/auth", z.Authentication)
	router.Handle("/profile", mw.RequireAuthentication()(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authCtx := authentication.Context[*openid.UserInfoContext](req.Context())
		data, err := json.Marshal(authCtx)
		_ = err
		err = t.ExecuteTemplate(w, "profile.html", string(data))
		_ = err
	})))
	router.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		err = t.ExecuteTemplate(w, "home.html", &struct {
			IsAdmin bool
			Tasks   []string
		}{
			IsAdmin: true,
			Tasks:   tasks,
		})
		_ = err
	}))

	// start the server on the specified port (default http://localhost:8089)
	lis := fmt.Sprintf(":%s", *port)
	slog.Info("server listening, press ctrl+c to stop", "addr", "http://localhost"+lis)
	err = http.ListenAndServe(lis, router)
	if !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server terminated", "error", err)
		os.Exit(1)
	}
}

func parseTemplates() {

}
