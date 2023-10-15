package v2beta

import (
	"github.com/zitadel/zitadel-go/v2/pkg/client/zitadel"
	user "github.com/zitadel/zitadel-go/v2/pkg/client/zitadel/user/v2beta"
)

type Client struct {
	Connection *zitadel.Connection
	user.UserServiceClient
}

func NewClient(issuer, api string, scopes []string, options ...zitadel.Option) (*Client, error) {

	conn, err := zitadel.NewConnection(issuer, api, scopes, options...)
	if err != nil {
		return nil, err
	}

	return &Client{
		Connection:        conn,
		UserServiceClient: user.NewUserServiceClient(conn.ClientConn),
	}, nil
}
