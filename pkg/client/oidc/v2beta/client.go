package v2beta

import (
	"github.com/zitadel/zitadel-go/v2/pkg/client/zitadel"
	oidc "github.com/zitadel/zitadel-go/v2/pkg/client/zitadel/oidc/v2beta"
)

type Client struct {
	Connection *zitadel.Connection
	oidc.OIDCServiceClient
}

func NewClient(issuer, api string, scopes []string, options ...zitadel.Option) (*Client, error) {

	conn, err := zitadel.NewConnection(issuer, api, scopes, options...)
	if err != nil {
		return nil, err
	}

	return &Client{
		Connection:        conn,
		OIDCServiceClient: oidc.NewOIDCServiceClient(conn.ClientConn),
	}, nil
}
