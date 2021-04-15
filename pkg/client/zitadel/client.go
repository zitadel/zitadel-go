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
	issuer   string
	api      string
	keyPath  string
	scopes   []string
	orgID    string
	insecure bool
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
	dialOptions := []grpc.DialOption{
		grpc.WithChainUnaryInterceptor(
			unaryInterceptors...,
		),
		grpc.WithChainStreamInterceptor(
			streamInterceptors...,
		),
	}
	opt, err := transportOption(c.api, c.insecure)
	if err != nil {
		return nil, err
	}
	dialOptions = append(dialOptions, opt)
	conn, err := grpc.Dial(c.api, dialOptions...)
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

func transportOption(api string, insecure bool) (grpc.DialOption, error) {
	if insecure {
		return grpc.WithInsecure(), nil
	}
	certs, err := transportCredentials(api)
	if err != nil {
		return nil, err
	}
	return grpc.WithTransportCredentials(certs), nil
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

//WithCustomURL replaces the standard issuer (https://issuer.zitadel.ch) and api endpoint (api.zitadel.ch:443)
func WithCustomURL(issuer, api string) func(*Connection) error {
	return func(client *Connection) error {
		client.issuer = issuer
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
//if not set the resource owner (organisation) of the calling user will be used
func WithOrgID(orgID string) func(*Connection) error {
	return func(client *Connection) error {
		client.orgID = orgID
		return nil
	}
}

//WithInsecure disables transport security for the client connection
//use only when absolutely necessary (local development)
func WithInsecure() func(*Connection) error {
	return func(client *Connection) error {
		client.insecure = true
		return nil
	}
}
