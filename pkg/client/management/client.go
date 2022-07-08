package management

import (
	"github.com/zitadel/zitadel-go/v2/pkg/client/zitadel"
	"github.com/zitadel/zitadel-go/v2/pkg/client/zitadel/management"
)

type Client struct {
	Connection *zitadel.Connection
	management.ManagementServiceClient
}

func NewClient(issuer, api string, scopes []string, options ...zitadel.Option) (*Client, error) {
	conn, err := zitadel.NewConnection(issuer, api, scopes, options...)
	if err != nil {
		return nil, err
	}
	return &Client{
		Connection:              conn,
		ManagementServiceClient: management.NewManagementServiceClient(conn.ClientConn),
	}, nil
}
