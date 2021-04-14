package management

import (
	"github.com/caos/zitadel-go/pkg/client/zitadel"
	"github.com/caos/zitadel-go/pkg/client/zitadel/management"
)

type Client struct {
	Connection *zitadel.Connection
	management.ManagementServiceClient
}

func NewClient(scopes []string, options ...zitadel.Option) (*Client, error) {
	conn, err := zitadel.NewConnection(scopes, options...)
	if err != nil {
		return nil, err
	}
	return &Client{
		Connection:              conn,
		ManagementServiceClient: management.NewManagementServiceClient(conn.ClientConn),
	}, nil
}
