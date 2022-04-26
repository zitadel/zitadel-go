package main

import (
	"log"
	"net/http"
	"time"

	http_mw "github.com/zitadel/zitadel-go/pkg/api/middleware/http"
	"github.com/zitadel/zitadel-go/pkg/client"
	"github.com/zitadel/zitadel-go/pkg/client/middleware"
)

func main() {
	introspection, err := http_mw.NewIntrospectionInterceptor(client.Issuer, middleware.OSKeyPath())
	if err != nil {
		log.Fatal(err)
	}

	router := http.NewServeMux()
	router.HandleFunc("/public", writeOK)
	router.HandleFunc("/protected", introspection.HandlerFunc(writeOK))

	lis := "127.0.0.1:5001"
	log.Fatal(http.ListenAndServe(lis, router))
}

func writeOK(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK " + time.Now().String()))
}
