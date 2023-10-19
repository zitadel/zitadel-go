package v2beta

import (
	"github.com/zitadel/zitadel-go/v2/pkg/client/zitadel"
	org "github.com/zitadel/zitadel-go/v2/pkg/client/zitadel/org/v2beta"
)

type Client struct {
	Connection *zitadel.Connection
	org.OrganizationServiceClient
}

func NewClient(issuer, api string, scopes []string, options ...zitadel.Option) (*Client, error) {

	conn, err := zitadel.NewConnection(issuer, api, scopes, options...)
	if err != nil {
		return nil, err
	}

	return &Client{
		Connection:                conn,
		OrganizationServiceClient: org.NewOrganizationServiceClient(conn.ClientConn),
	}, nil
}
