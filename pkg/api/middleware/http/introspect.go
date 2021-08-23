package http

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/caos/oidc/pkg/client/rs"
	"github.com/caos/oidc/pkg/oidc"

	"github.com/caos/zitadel-go/pkg/api/middleware"
)

type IntrospectionInterceptor struct {
	resourceServer rs.ResourceServer
	handler        http.Handler
	marshaller     Marshaller
	ignoredPaths   []string
	introspectOpts []func(oidc.IntrospectionResponse) error
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

func WithIgnoredPaths(paths ...string) func(*IntrospectionInterceptor) {
	return func(interceptor *IntrospectionInterceptor) {
		interceptor.ignoredPaths = paths
	}
}

func WithIntrospectionOptions(opts ...func(oidc.IntrospectionResponse) error) func(*IntrospectionInterceptor) {
	return func(interceptor *IntrospectionInterceptor) {
		interceptor.introspectOpts = opts
	}
}

//NewIntrospectionInterceptor intercepts every call and checks for a correct Bearer token using OAuth2 introspection
//by sending the token to the introspection endpoint)
func NewIntrospectionInterceptor(issuer, keyPath string, opts ...func(*IntrospectionInterceptor)) (*IntrospectionInterceptor, error) {
	resourceServer, err := rs.NewResourceServerFromKeyFile(issuer, keyPath)
	if err != nil {
		return nil, err
	}
	interceptor := &IntrospectionInterceptor{
		resourceServer: resourceServer,
		marshaller:     &JSONMarshaller{},
	}
	for _, opt := range opts {
		opt(interceptor)
	}
	return interceptor, nil
}

//Handler creates a http.Handler for middleware usage
func (interceptor *IntrospectionInterceptor) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, path := range interceptor.ignoredPaths {
			if path == r.URL.Path {
				next.ServeHTTP(w, r)
				return
			}
		}
		ctx, err := interceptor.introspect(r)
		if err != nil {
			interceptor.writeError(w, 401, err.Error())
			return
		}
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

//HandlerFunc creates a http.HandlerFunc for middleware usage
func (interceptor *IntrospectionInterceptor) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, path := range interceptor.ignoredPaths {
			if path == r.URL.Path {
				next.ServeHTTP(w, r)
				return
			}
		}
		ctx, err := interceptor.introspect(r)
		if err != nil {
			interceptor.writeError(w, 401, err.Error())
			return
		}
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	}
}

func (interceptor *IntrospectionInterceptor) introspect(r *http.Request) (context.Context, error) {
	ctx := r.Context()
	response, err := middleware.Introspect(ctx, r.Header.Get("authorization"), interceptor.resourceServer, interceptor.introspectOpts...)
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, middleware.INTROSPECTION, response), nil
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
