package http

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/zitadel/oidc/pkg/client/rs"

	"github.com/zitadel/zitadel-go/v2/pkg/api/middleware"
)

type IntrospectionInterceptor struct {
	resourceServer rs.ResourceServer
	handler        http.Handler
	marshaller     Marshaller
}

type Marshaller interface {
	Marshal(interface{}) ([]byte, error)
	ContentType() string
}

type JSONMarshaller struct{}

func (j JSONMarshaller) Marshal(i interface{}) ([]byte, error) {
	return json.Marshal(i)
}

func (j JSONMarshaller) ContentType() string {
	return "application/json"
}

//NewIntrospectionInterceptor intercepts every call and checks for a correct Bearer token using OAuth2 introspection
//by sending the token to the introspection endpoint)
func NewIntrospectionInterceptor(issuer, keyPath string) (*IntrospectionInterceptor, error) {
	resourceServer, err := rs.NewResourceServerFromKeyFile(issuer, keyPath)
	if err != nil {
		return nil, err
	}
	return &IntrospectionInterceptor{
		resourceServer: resourceServer,
		marshaller:     &JSONMarshaller{},
	}, nil
}

//Handler creates a http.Handler for middleware usage
func (interceptor *IntrospectionInterceptor) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := interceptor.introspect(r)
		if err != nil {
			interceptor.writeError(w, 401, err.Error())
			return
		}
		next.ServeHTTP(w, r)
	})
}

//HandlerFunc creates a http.HandlerFunc for middleware usage
func (interceptor *IntrospectionInterceptor) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := interceptor.introspect(r)
		if err != nil {
			interceptor.writeError(w, 401, err.Error())
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (interceptor *IntrospectionInterceptor) introspect(r *http.Request) error {
	return middleware.Introspect(r.Context(), r.Header.Get("authorization"), interceptor.resourceServer)
}

func (interceptor *IntrospectionInterceptor) writeError(w http.ResponseWriter, status int, errMessage interface{}) {
	b, err := interceptor.marshaller.Marshal(errMessage)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", interceptor.marshaller.ContentType())
	w.WriteHeader(status)
	_, err = w.Write(b)
	if err != nil {
		log.Println("error writing response")
	}
}
