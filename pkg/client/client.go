package client

import (
	"context"

	"golang.org/x/oauth2"
	"google.golang.org/grpc"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/admin"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/auth"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	oidcV2_pb "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/oidc/v2"
	oidcV2Beta_pb "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/oidc/v2beta"
	orgV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/org/v2"
	orgV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/org/v2beta"
	sessionV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/session/v2"
	sessionV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/session/v2beta"
	settingsV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/settings/v2"
	settingsV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/settings/v2beta"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/system"
	userV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	userV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2beta"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

type clientOptions struct {
	initTokenSource TokenSourceInitializer
	grpcDialOptions []grpc.DialOption
}

type Option func(*clientOptions)

// WithAuth allows to set a token source as authorization, e.g. [PAT], resp. provide an authentication mechanism,
// such as JWT Profile ([JWTAuthentication]) or Password ([PasswordAuthentication]) for service users.
func WithAuth(initTokenSource TokenSourceInitializer) Option {
	return func(c *clientOptions) {
		c.initTokenSource = initTokenSource
	}
}

// WithGRPCDialOptions allows to use custom grpc dial options when establishing connection with Zitadel.
// Multiple calls to WithGRPCDialOptions is allowed, options will be appended.
func WithGRPCDialOptions(opts ...grpc.DialOption) Option {
	return func(c *clientOptions) {
		c.grpcDialOptions = append(c.grpcDialOptions, opts...)
	}
}

type Client struct {
	connection *grpc.ClientConn

	systemService         system.SystemServiceClient
	adminService          admin.AdminServiceClient
	managementService     management.ManagementServiceClient
	userService           userV2Beta.UserServiceClient
	userServiceV2         userV2.UserServiceClient
	authService           auth.AuthServiceClient
	settingsService       settingsV2Beta.SettingsServiceClient
	settingsServiceV2     settingsV2.SettingsServiceClient
	sessionService        sessionV2Beta.SessionServiceClient
	sessionServiceV2      sessionV2.SessionServiceClient
	organizationService   orgV2Beta.OrganizationServiceClient
	organizationServiceV2 orgV2.OrganizationServiceClient
	oidcService           oidcV2Beta_pb.OIDCServiceClient
	oidcServiceV2         oidcV2_pb.OIDCServiceClient
}

func New(ctx context.Context, zitadel *zitadel.Zitadel, opts ...Option) (*Client, error) {
	var options clientOptions
	for _, o := range opts {
		o(&options)
	}

	var source oauth2.TokenSource
	if options.initTokenSource != nil {
		var err error
		source, err = options.initTokenSource(ctx, zitadel.Origin())
		if err != nil {
			return nil, err
		}
	}

	conn, err := newConnection(ctx, zitadel, source, options.grpcDialOptions...)
	if err != nil {
		return nil, err
	}

	return &Client{
		connection: conn,
	}, nil
}

func newConnection(
	ctx context.Context,
	zitadel *zitadel.Zitadel,
	tokenSource oauth2.TokenSource,
	opts ...grpc.DialOption,
) (*grpc.ClientConn, error) {
	transportCreds, err := transportCredentials(zitadel.Domain(), zitadel.IsTLS())
	if err != nil {
		return nil, err
	}

	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithPerRPCCredentials(&cred{tls: zitadel.IsTLS(), tokenSource: tokenSource}),
	}
	dialOptions = append(dialOptions, opts...)

	return grpc.DialContext(ctx, zitadel.Host(), dialOptions...)
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

func (c *Client) UserService() userV2Beta.UserServiceClient {
	if c.userService == nil {
		c.userService = userV2Beta.NewUserServiceClient(c.connection)
	}
	return c.userService
}

func (c *Client) UserServiceV2() userV2.UserServiceClient {
	if c.userServiceV2 == nil {
		c.userServiceV2 = userV2.NewUserServiceClient(c.connection)
	}
	return c.userServiceV2
}

func (c *Client) SettingsService() settingsV2Beta.SettingsServiceClient {
	if c.settingsService == nil {
		c.settingsService = settingsV2Beta.NewSettingsServiceClient(c.connection)
	}
	return c.settingsService
}

func (c *Client) SettingsServiceV2() settingsV2.SettingsServiceClient {
	if c.settingsServiceV2 == nil {
		c.settingsServiceV2 = settingsV2.NewSettingsServiceClient(c.connection)
	}
	return c.settingsServiceV2
}

func (c *Client) SessionService() sessionV2Beta.SessionServiceClient {
	if c.sessionService == nil {
		c.sessionService = sessionV2Beta.NewSessionServiceClient(c.connection)
	}
	return c.sessionService
}

func (c *Client) SessionServiceV2() sessionV2.SessionServiceClient {
	if c.sessionServiceV2 == nil {
		c.sessionServiceV2 = sessionV2.NewSessionServiceClient(c.connection)
	}
	return c.sessionServiceV2
}

func (c *Client) OIDCService() oidcV2Beta_pb.OIDCServiceClient {
	if c.oidcService == nil {
		c.oidcService = oidcV2Beta_pb.NewOIDCServiceClient(c.connection)
	}
	return c.oidcService
}

func (c *Client) OIDCServiceV2() oidcV2_pb.OIDCServiceClient {
	if c.oidcServiceV2 == nil {
		c.oidcServiceV2 = oidcV2_pb.NewOIDCServiceClient(c.connection)
	}
	return c.oidcServiceV2
}

func (c *Client) OrganizationService() orgV2Beta.OrganizationServiceClient {
	if c.organizationService == nil {
		c.organizationService = orgV2Beta.NewOrganizationServiceClient(c.connection)
	}
	return c.organizationService
}

func (c *Client) OrganizationServiceV2() orgV2.OrganizationServiceClient {
	if c.organizationServiceV2 == nil {
		c.organizationServiceV2 = orgV2.NewOrganizationServiceClient(c.connection)
	}
	return c.organizationServiceV2
}
