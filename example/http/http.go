package main

import (
	"log"
	"net/http"
	"time"

	http_mw "github.com/caos/zitadel-go/pkg/api/middleware/http"
)

func main() {
	introspection, err := http_mw.NewIntrospectionInterceptor("https://issuer.zitadel.dev", "/Users/livio/Downloads/dev-api-103821073161710129.json")
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
