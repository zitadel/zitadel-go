package client

import (
	"context"

	"golang.org/x/oauth2"
	"google.golang.org/grpc"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/admin"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/auth"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	oidc_pb "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/oidc/v2beta"
	org "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/org/v2beta"
	session "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/session/v2beta"
	settings "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/settings/v2beta"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/system"
	user "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2beta"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

type Client struct {
	initTokenSource TokenSourceInitializer
	connection      *grpc.ClientConn

	systemService       system.SystemServiceClient
	adminService        admin.AdminServiceClient
	managementService   management.ManagementServiceClient
	userService         user.UserServiceClient
	authService         auth.AuthServiceClient
	settingsService     settings.SettingsServiceClient
	sessionService      session.SessionServiceClient
	organizationService org.OrganizationServiceClient
	oidcService         oidc_pb.OIDCServiceClient
}

type Option func(*Client)

// WithAuth allows to set a token source as authorization, e.g. [PAT], resp. provide an authentication mechanism,
// such as JWT Profile ([JWTAuthentication]) or Password ([PasswordAuthentication]) for service users.
func WithAuth(initTokenSource TokenSourceInitializer) Option {
	return func(c *Client) {
		c.initTokenSource = initTokenSource
	}
}

func New(ctx context.Context, zitadel *zitadel.Zitadel, options ...Option) (_ *Client, err error) {
	c := &Client{}
	for _, option := range options {
		option(c)
	}
	var source oauth2.TokenSource
	if c.initTokenSource != nil {
		source, err = c.initTokenSource(ctx, zitadel.Origin())
		if err != nil {
			return nil, err
		}
	}
	err = c.newConnection(ctx, zitadel, source)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) newConnection(ctx context.Context, zitadel *zitadel.Zitadel, tokenSource oauth2.TokenSource) error {
	transportCreds, err := transportCredentials(zitadel.Domain(), zitadel.IsTLS())
	if err != nil {
		return err
	}
	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithPerRPCCredentials(&cred{tls: zitadel.IsTLS(), tokenSource: tokenSource}),
	}
	c.connection, err = grpc.DialContext(ctx, zitadel.Host(), dialOptions...)
	return err
}

func (c *Client) SystemService() system.SystemServiceClient {
	if c.systemService == nil {
		c.systemService = system.NewSystemServiceClient(c.connection)
	}
	return c.systemService
}

func (c *Client) AdminService() admin.AdminServiceClient {
	if c.adminService == nil {
		c.adminService = admin.NewAdminServiceClient(c.connection)
	}
	return c.adminService
}

func (c *Client) ManagementService() management.ManagementServiceClient {
	if c.managementService == nil {
		c.managementService = management.NewManagementServiceClient(c.connection)
	}
	return c.managementService
}

func (c *Client) AuthService() auth.AuthServiceClient {
	if c.authService == nil {
		c.authService = auth.NewAuthServiceClient(c.connection)
	}
	return c.authService
}

func (c *Client) UserService() user.UserServiceClient {
	if c.userService == nil {
		c.userService = user.NewUserServiceClient(c.connection)
	}
	return c.userService
}

func (c *Client) SettingsService() settings.SettingsServiceClient {
	if c.settingsService == nil {
		c.settingsService = settings.NewSettingsServiceClient(c.connection)
	}
	return c.settingsService
}

func (c *Client) SessionService() session.SessionServiceClient {
	if c.sessionService == nil {
		c.sessionService = session.NewSessionServiceClient(c.connection)
	}
	return c.sessionService
}

func (c *Client) OIDCService() oidc_pb.OIDCServiceClient {
	if c.oidcService == nil {
		c.oidcService = oidc_pb.NewOIDCServiceClient(c.connection)
	}
	return c.oidcService
}

func (c *Client) OrganizationService() org.OrganizationServiceClient {
	if c.organizationService == nil {
		c.organizationService = org.NewOrganizationServiceClient(c.connection)
	}
	return c.organizationService
}
