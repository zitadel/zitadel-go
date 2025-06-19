package client

import (
	"context"
	"sync"

	"golang.org/x/oauth2"
	"google.golang.org/grpc"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/admin"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/auth"
	featureV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/feature/v2"
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
	webkeyV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/webkey/v2beta"
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

type Lazy[T any] struct {
	once  sync.Once
	value T
}

func (l *Lazy[T]) Get(init func() T) T {
	l.once.Do(func() {
		l.value = init()
	})
	return l.value
}

type Client struct {
	connection *grpc.ClientConn

	systemService         Lazy[system.SystemServiceClient]
	adminService          Lazy[admin.AdminServiceClient]
	managementService     Lazy[management.ManagementServiceClient]
	userService           Lazy[userV2Beta.UserServiceClient]
	userServiceV2         Lazy[userV2.UserServiceClient]
	authService           Lazy[auth.AuthServiceClient]
	settingsService       Lazy[settingsV2Beta.SettingsServiceClient]
	settingsServiceV2     Lazy[settingsV2.SettingsServiceClient]
	sessionService        Lazy[sessionV2Beta.SessionServiceClient]
	sessionServiceV2      Lazy[sessionV2.SessionServiceClient]
	organizationService   Lazy[orgV2Beta.OrganizationServiceClient]
	organizationServiceV2 Lazy[orgV2.OrganizationServiceClient]
	oidcService           Lazy[oidcV2Beta_pb.OIDCServiceClient]
	oidcServiceV2         Lazy[oidcV2_pb.OIDCServiceClient]
	featureV2             Lazy[featureV2.FeatureServiceClient]
	webkeyV2Beta          Lazy[webkeyV2Beta.WebKeyServiceClient]
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
	transportCreds, err := transportCredentials(zitadel.Domain(), zitadel.IsTLS(), zitadel.IsInsecureSkipVerifyTLS())
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
	return c.systemService.Get(func() system.SystemServiceClient {
		return system.NewSystemServiceClient(c.connection)
	})
}

func (c *Client) AdminService() admin.AdminServiceClient {
	return c.adminService.Get(func() admin.AdminServiceClient {
		return admin.NewAdminServiceClient(c.connection)
	})
}

func (c *Client) ManagementService() management.ManagementServiceClient {
	return c.managementService.Get(func() management.ManagementServiceClient {
		return management.NewManagementServiceClient(c.connection)
	})
}

func (c *Client) AuthService() auth.AuthServiceClient {
	return c.authService.Get(func() auth.AuthServiceClient {
		return auth.NewAuthServiceClient(c.connection)
	})
}

func (c *Client) UserService() userV2Beta.UserServiceClient {
	return c.userService.Get(func() userV2Beta.UserServiceClient {
		return userV2Beta.NewUserServiceClient(c.connection)
	})
}

func (c *Client) UserServiceV2() userV2.UserServiceClient {
	return c.userServiceV2.Get(func() userV2.UserServiceClient {
		return userV2.NewUserServiceClient(c.connection)
	})
}

func (c *Client) SettingsService() settingsV2Beta.SettingsServiceClient {
	return c.settingsService.Get(func() settingsV2Beta.SettingsServiceClient {
		return settingsV2Beta.NewSettingsServiceClient(c.connection)
	})
}

func (c *Client) SettingsServiceV2() settingsV2.SettingsServiceClient {
	return c.settingsServiceV2.Get(func() settingsV2.SettingsServiceClient {
		return settingsV2.NewSettingsServiceClient(c.connection)
	})
}

func (c *Client) SessionService() sessionV2Beta.SessionServiceClient {
	return c.sessionService.Get(func() sessionV2Beta.SessionServiceClient {
		return sessionV2Beta.NewSessionServiceClient(c.connection)
	})
}

func (c *Client) SessionServiceV2() sessionV2.SessionServiceClient {
	return c.sessionServiceV2.Get(func() sessionV2.SessionServiceClient {
		return sessionV2.NewSessionServiceClient(c.connection)
	})
}

func (c *Client) OIDCService() oidcV2Beta_pb.OIDCServiceClient {
	return c.oidcService.Get(func() oidcV2Beta_pb.OIDCServiceClient {
		return oidcV2Beta_pb.NewOIDCServiceClient(c.connection)
	})
}

func (c *Client) OIDCServiceV2() oidcV2_pb.OIDCServiceClient {
	return c.oidcServiceV2.Get(func() oidcV2_pb.OIDCServiceClient {
		return oidcV2_pb.NewOIDCServiceClient(c.connection)
	})
}

func (c *Client) OrganizationService() orgV2Beta.OrganizationServiceClient {
	return c.organizationService.Get(func() orgV2Beta.OrganizationServiceClient {
		return orgV2Beta.NewOrganizationServiceClient(c.connection)
	})
}

func (c *Client) OrganizationServiceV2() orgV2.OrganizationServiceClient {
	return c.organizationServiceV2.Get(func() orgV2.OrganizationServiceClient {
		return orgV2.NewOrganizationServiceClient(c.connection)
	})
}

func (c *Client) FeatureServiceV2() featureV2.FeatureServiceClient {
	return c.featureV2.Get(func() featureV2.FeatureServiceClient {
		return featureV2.NewFeatureServiceClient(c.connection)
	})
}

func (c *Client) WebkeyServiceV2Beta() webkeyV2Beta.WebKeyServiceClient {
	return c.webkeyV2Beta.Get(func() webkeyV2Beta.WebKeyServiceClient {
		return webkeyV2Beta.NewWebKeyServiceClient(c.connection)
	})
}
