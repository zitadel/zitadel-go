package client

import (
	"context"
	"sync"

	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	actionV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/action/v2"
	actionV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/action/v2beta"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/admin"
	analyticsV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/analytics/v2beta"
	appV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/app/v2beta"
	applicationV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/auth"
	authorizationV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	authorizationV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2beta"
	featureV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/feature/v2"
	featureV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/feature/v2beta"
	idpV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/idp/v2"
	instanceV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/instance/v2"
	instanceV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/instance/v2beta"
	internalPermissionV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/internal_permission/v2"
	internalPermissionV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/internal_permission/v2beta"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	oidcV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/oidc/v2"
	oidcV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/oidc/v2beta"
	orgV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/org/v2"
	orgV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/org/v2beta"
	projectV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2"
	projectV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2beta"
	samlV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/saml/v2"
	sessionV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/session/v2"
	sessionV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/session/v2beta"
	settingsV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/settings/v2"
	settingsV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/settings/v2beta"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/system"
	userV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	userV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2beta"
	webkeyV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/webkey/v2"
	webkeyV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/webkey/v2beta"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

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

	actionServiceV2                 Lazy[actionV2.ActionServiceClient]
	actionServiceV2Beta             Lazy[actionV2Beta.ActionServiceClient]
	authorizationServiceV2          Lazy[authorizationV2.AuthorizationServiceClient]
	authorizationServiceV2Beta      Lazy[authorizationV2Beta.AuthorizationServiceClient]
	adminService                    Lazy[admin.AdminServiceClient]
	systemService                   Lazy[system.SystemServiceClient]
	managementService               Lazy[management.ManagementServiceClient]
	authService                     Lazy[auth.AuthServiceClient]
	settingsService                 Lazy[settingsV2Beta.SettingsServiceClient]
	settingsServiceV2               Lazy[settingsV2.SettingsServiceClient]
	internalPermissionServiceV2     Lazy[internalPermissionV2.InternalPermissionServiceClient]
	internalPermissionServiceV2Beta Lazy[internalPermissionV2Beta.InternalPermissionServiceClient]
	sessionService                  Lazy[sessionV2Beta.SessionServiceClient]
	sessionServiceV2                Lazy[sessionV2.SessionServiceClient]
	organizationService             Lazy[orgV2Beta.OrganizationServiceClient]
	organizationServiceV2           Lazy[orgV2.OrganizationServiceClient]
	oidcService                     Lazy[oidcV2Beta.OIDCServiceClient]
	oidcServiceV2                   Lazy[oidcV2.OIDCServiceClient]
	userService                     Lazy[userV2Beta.UserServiceClient]
	userServiceV2                   Lazy[userV2.UserServiceClient]
	webkeyServiceV2                 Lazy[webkeyV2.WebKeyServiceClient]
	webkeyServiceV2Beta             Lazy[webkeyV2Beta.WebKeyServiceClient]
	applicationServiceV2            Lazy[applicationV2.ApplicationServiceClient]
	appServiceV2Beta                Lazy[appV2Beta.AppServiceClient]
	telemetryServiceV2Beta          Lazy[analyticsV2Beta.TelemetryServiceClient]
	featureServiceV2                Lazy[featureV2.FeatureServiceClient]
	featureServiceV2Beta            Lazy[featureV2Beta.FeatureServiceClient]
	idpServiceV2                    Lazy[idpV2.IdentityProviderServiceClient]
	instanceServiceV2               Lazy[instanceV2.InstanceServiceClient]
	instanceServiceV2Beta           Lazy[instanceV2Beta.InstanceServiceClient]
	projectServiceV2                Lazy[projectV2.ProjectServiceClient]
	projectServiceV2Beta            Lazy[projectV2Beta.ProjectServiceClient]
	samlServiceV2                   Lazy[samlV2.SAMLServiceClient]
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

	// Interceptor to inject custom headers (e.g. Proxy-Auth) into metadata
	headerUnaryInterceptor := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if h := zitadel.Headers(); len(h) > 0 {
			kv := make([]string, 0, len(h)*2)
			for k, vv := range h {
				for _, v := range vv {
					kv = append(kv, k, v)
				}
			}
			ctx = metadata.AppendToOutgoingContext(ctx, kv...)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}

	headerStreamInterceptor := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		if h := zitadel.Headers(); len(h) > 0 {
			kv := make([]string, 0, len(h)*2)
			for k, vv := range h {
				for _, v := range vv {
					kv = append(kv, k, v)
				}
			}
			ctx = metadata.AppendToOutgoingContext(ctx, kv...)
		}
		return streamer(ctx, desc, cc, method, opts...)
	}

	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithPerRPCCredentials(&cred{tls: zitadel.IsTLS(), tokenSource: tokenSource}),
		grpc.WithChainUnaryInterceptor(headerUnaryInterceptor),
		grpc.WithChainStreamInterceptor(headerStreamInterceptor),
	}
	dialOptions = append(dialOptions, opts...)

	return grpc.DialContext(ctx, zitadel.Host(), dialOptions...)
}

// Deprecated: use ActionServiceV2 instead
func (c *Client) ActionServiceV2Beta() actionV2Beta.ActionServiceClient {
	return c.actionServiceV2Beta.Get(func() actionV2Beta.ActionServiceClient {
		return actionV2Beta.NewActionServiceClient(c.connection)
	})
}

func (c *Client) ActionServiceV2() actionV2.ActionServiceClient {
	return c.actionServiceV2.Get(func() actionV2.ActionServiceClient {
		return actionV2.NewActionServiceClient(c.connection)
	})
}

func (c *Client) AdminService() admin.AdminServiceClient {
	return c.adminService.Get(func() admin.AdminServiceClient {
		return admin.NewAdminServiceClient(c.connection)
	})
}

func (c *Client) TelemetryServiceV2Beta() analyticsV2Beta.TelemetryServiceClient {
	return c.telemetryServiceV2Beta.Get(func() analyticsV2Beta.TelemetryServiceClient {
		return analyticsV2Beta.NewTelemetryServiceClient(c.connection)
	})
}

// Deprecated: use ApplicationServiceV2 instead
func (c *Client) AppServiceV2Beta() appV2Beta.AppServiceClient {
	return c.appServiceV2Beta.Get(func() appV2Beta.AppServiceClient {
		return appV2Beta.NewAppServiceClient(c.connection)
	})
}

func (c *Client) ApplicationServiceV2() applicationV2.ApplicationServiceClient {
	return c.applicationServiceV2.Get(func() applicationV2.ApplicationServiceClient {
		return applicationV2.NewApplicationServiceClient(c.connection)
	})
}

func (c *Client) AuthService() auth.AuthServiceClient {
	return c.authService.Get(func() auth.AuthServiceClient {
		return auth.NewAuthServiceClient(c.connection)
	})
}

// Deprecated: use AuthorizationServiceV2 instead
func (c *Client) AuthorizationServiceV2Beta() authorizationV2Beta.AuthorizationServiceClient {
	return c.authorizationServiceV2Beta.Get(func() authorizationV2Beta.AuthorizationServiceClient {
		return authorizationV2Beta.NewAuthorizationServiceClient(c.connection)
	})
}

func (c *Client) AuthorizationServiceV2() authorizationV2.AuthorizationServiceClient {
	return c.authorizationServiceV2.Get(func() authorizationV2.AuthorizationServiceClient {
		return authorizationV2.NewAuthorizationServiceClient(c.connection)
	})
}

// Deprecated: use FeatureServiceV2 instead
func (c *Client) FeatureServiceV2Beta() featureV2Beta.FeatureServiceClient {
	return c.featureServiceV2Beta.Get(func() featureV2Beta.FeatureServiceClient {
		return featureV2Beta.NewFeatureServiceClient(c.connection)
	})
}

func (c *Client) FeatureServiceV2() featureV2.FeatureServiceClient {
	return c.featureServiceV2.Get(func() featureV2.FeatureServiceClient {
		return featureV2.NewFeatureServiceClient(c.connection)
	})
}

// Deprecated: use InstanceServiceV2 instead
func (c *Client) InstanceServiceV2Beta() instanceV2Beta.InstanceServiceClient {
	return c.instanceServiceV2Beta.Get(func() instanceV2Beta.InstanceServiceClient {
		return instanceV2Beta.NewInstanceServiceClient(c.connection)
	})
}

func (c *Client) InstanceServiceV2() instanceV2.InstanceServiceClient {
	return c.instanceServiceV2.Get(func() instanceV2.InstanceServiceClient {
		return instanceV2.NewInstanceServiceClient(c.connection)
	})
}

// Deprecated: use InternalPermissionServiceV2 instead
func (c *Client) InternalPermissionServiceV2Beta() internalPermissionV2Beta.InternalPermissionServiceClient {
	return c.internalPermissionServiceV2Beta.Get(func() internalPermissionV2Beta.InternalPermissionServiceClient {
		return internalPermissionV2Beta.NewInternalPermissionServiceClient(c.connection)
	})
}

func (c *Client) InternalPermissionServiceV2() internalPermissionV2.InternalPermissionServiceClient {
	return c.internalPermissionServiceV2.Get(func() internalPermissionV2.InternalPermissionServiceClient {
		return internalPermissionV2.NewInternalPermissionServiceClient(c.connection)
	})
}

func (c *Client) ManagementService() management.ManagementServiceClient {
	return c.managementService.Get(func() management.ManagementServiceClient {
		return management.NewManagementServiceClient(c.connection)
	})
}

func (c *Client) IdpServiceV2() idpV2.IdentityProviderServiceClient {
	return c.idpServiceV2.Get(func() idpV2.IdentityProviderServiceClient {
		return idpV2.NewIdentityProviderServiceClient(c.connection)
	})
}

// Deprecated: use OIDCServiceV2 instead
func (c *Client) OIDCService() oidcV2Beta.OIDCServiceClient {
	return c.oidcService.Get(func() oidcV2Beta.OIDCServiceClient {
		return oidcV2Beta.NewOIDCServiceClient(c.connection)
	})
}

func (c *Client) OIDCServiceV2() oidcV2.OIDCServiceClient {
	return c.oidcServiceV2.Get(func() oidcV2.OIDCServiceClient {
		return oidcV2.NewOIDCServiceClient(c.connection)
	})
}

// Deprecated: use OrganizationServiceV2 instead
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

// Deprecated: use ProjectServiceV2 instead
func (c *Client) ProjectServiceV2Beta() projectV2Beta.ProjectServiceClient {
	return c.projectServiceV2Beta.Get(func() projectV2Beta.ProjectServiceClient {
		return projectV2Beta.NewProjectServiceClient(c.connection)
	})
}

func (c *Client) ProjectServiceV2() projectV2.ProjectServiceClient {
	return c.projectServiceV2.Get(func() projectV2.ProjectServiceClient {
		return projectV2.NewProjectServiceClient(c.connection)
	})
}

func (c *Client) SAMLServiceV2() samlV2.SAMLServiceClient {
	return c.samlServiceV2.Get(func() samlV2.SAMLServiceClient {
		return samlV2.NewSAMLServiceClient(c.connection)
	})
}

// Deprecated: use SessionServiceV2 instead
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

// Deprecated: use SettingsServiceV2 instead
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

func (c *Client) SystemService() system.SystemServiceClient {
	return c.systemService.Get(func() system.SystemServiceClient {
		return system.NewSystemServiceClient(c.connection)
	})
}

// Deprecated: use UserServiceV2 instead
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

// Deprecated: use WebkeyServiceV2 instead
func (c *Client) WebkeyServiceV2() webkeyV2.WebKeyServiceClient {
	return c.webkeyServiceV2.Get(func() webkeyV2.WebKeyServiceClient {
		return webkeyV2.NewWebKeyServiceClient(c.connection)
	})
}

func (c *Client) WebkeyServiceV2Beta() webkeyV2Beta.WebKeyServiceClient {
	return c.webkeyServiceV2Beta.Get(func() webkeyV2Beta.WebKeyServiceClient {
		return webkeyV2Beta.NewWebKeyServiceClient(c.connection)
	})
}

func (c *Client) Close() error {
	return c.connection.Close()
}
