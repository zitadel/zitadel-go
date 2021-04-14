package zitadel

import (
	"crypto/x509"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/caos/zitadel-go/pkg/client"
	"github.com/caos/zitadel-go/pkg/client/middleware"
)

type Connection struct {
	issuer  string
	api     string
	keyPath string
	scopes  []string
	orgID   string
	*grpc.ClientConn
}

func NewConnection(scopes []string, options ...Option) (*Connection, error) {
	c := &Connection{
		issuer:  client.Issuer,
		api:     client.API,
		keyPath: middleware.OSKeyPath(),
		scopes:  scopes,
	}

	for _, option := range options {
		if err := option(c); err != nil {
			return nil, err
		}
	}
	unaryInterceptors, streamInterceptors, err := interceptors(c.issuer, c.keyPath, c.orgID, c.scopes)
	if err != nil {
		return nil, err
	}
	certs, err := transportCredentials(c.api)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.Dial(c.api,
		grpc.WithTransportCredentials(certs),
		grpc.WithChainUnaryInterceptor(
			unaryInterceptors...,
		),
		grpc.WithChainStreamInterceptor(
			streamInterceptors...,
		),
	)
	if err != nil {
		return nil, err
	}
	c.ClientConn = conn

	return c, nil
}

func interceptors(issuer, keyPath, orgID string, scopes []string) ([]grpc.UnaryClientInterceptor, []grpc.StreamClientInterceptor, error) {
	auth, err := middleware.NewAuthInterceptor(issuer, keyPath, scopes...)
	if err != nil {
		return nil, nil, err
	}
	unaryInterceptors := []grpc.UnaryClientInterceptor{auth.Unary()}
	streamInterceptors := []grpc.StreamClientInterceptor{auth.Stream()}
	if orgID != "" {
		org := middleware.NewOrgInterceptor(orgID)
		unaryInterceptors = append(unaryInterceptors, org.Unary())
		streamInterceptors = append(streamInterceptors, org.Stream())
	}
	return unaryInterceptors, streamInterceptors, nil
}

func transportCredentials(api string) (credentials.TransportCredentials, error) {
	ca, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if ca == nil {
		ca = x509.NewCertPool()
	}

	servernameWithoutPort := strings.Split(api, ":")[0]
	return credentials.NewClientTLSFromCert(ca, servernameWithoutPort), nil
}

type Option func(*Connection) error

//WithIssuer replaces the standard issuer (https://issuer.zitadel.ch)
func WithIssuer(issuer string) func(*Connection) error {
	return func(client *Connection) error {
		client.issuer = issuer
		return nil
	}
}

//WithAPI replaces the standard api (api.zitadel.ch:443)
func WithAPI(api string) func(*Connection) error {
	return func(client *Connection) error {
		client.api = api
		return nil
	}
}

//WithKeyPath sets the path to the key.json used for authentication
//if not set env var ZITADEL_KEY_PATH will be used
func WithKeyPath(keyPath string) func(*Connection) error {
	return func(client *Connection) error {
		client.keyPath = keyPath
		return nil
	}
}

//WithOrgID sets the organization context (where the api calls are executed)
func WithOrgID(orgID string) func(*Connection) error {
	return func(client *Connection) error {
		client.orgID = orgID
		return nil
	}
}
