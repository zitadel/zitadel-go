package main

import (
	"log"
	"net/http"
	"time"

	api_mw "github.com/caos/zitadel-go/pkg/api/middleware"
	http_mw "github.com/caos/zitadel-go/pkg/api/middleware/http"
	"github.com/caos/zitadel-go/pkg/client"
	"github.com/caos/zitadel-go/pkg/client/middleware"
)

func main() {
	introspection, err := http_mw.NewIntrospectionInterceptor(client.Issuer, middleware.OSKeyPath(),
		http_mw.WithIgnoredPaths("/public"),
		http_mw.WithIntrospectionOptions(api_mw.WithCheckClaim("email", "livio@caos.ch")),
	)
	if err != nil {
		log.Fatal(err)
	}

	router := http.NewServeMux()
	//router := mux.NewRouter()
	//router.Use(introspection.Handler)
	router.HandleFunc("/public", writeOK)
	router.HandleFunc("/protected", introspection.HandlerFunc(writeOK))

	lis := "127.0.0.1:5001"
	log.Fatal(http.ListenAndServe(lis, router))
}

func writeOK(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK " + time.Now().String()))
}
