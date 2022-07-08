package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	http_mw "github.com/zitadel/zitadel-go/v2/pkg/api/middleware/http"
	"github.com/zitadel/zitadel-go/v2/pkg/client/middleware"
)

var (
	issuer = flag.String("issuer", "", "issuer of your ZITADEL instance (in the form: https://<instance>.zitadel.cloud or https://<yourdomain>)")
)

func main() {
	flag.Parse()

	introspection, err := http_mw.NewIntrospectionInterceptor(*issuer, middleware.OSKeyPath())
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
