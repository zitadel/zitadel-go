package client

import (
	"context"

	"golang.org/x/oauth2"
	"google.golang.org/grpc"

	actionV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/action/v2beta"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/admin"
	analyticsV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/analytics/v2beta"
	appV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/app/v2beta"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/auth"
	authorizationV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2beta"
	featureV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/feature/v2"
	featureV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/feature/v2beta"
	idpV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/idp/v2"
	instanceV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/instance/v2beta"
	internalPermissionV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/internal_permission/v2beta"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	oidcV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/oidc/v2"
	oidcV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/oidc/v2beta"
	orgV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/org/v2"
	orgV2Beta "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/org/v2beta"
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

	actionServiceV2Beta             actionV2Beta.ActionServiceClient
	authorizationServiceV2Beta      authorizationV2Beta.AuthorizationServiceClient
	adminService                    admin.AdminServiceClient
	systemService                   system.SystemServiceClient
	managementService               management.ManagementServiceClient
	authService                     auth.AuthServiceClient
	settingsService                 settingsV2Beta.SettingsServiceClient
	settingsServiceV2               settingsV2.SettingsServiceClient
	internalPermissionServiceV2Beta internalPermissionV2Beta.InternalPermissionServiceClient
	sessionService                  sessionV2Beta.SessionServiceClient
	sessionServiceV2                sessionV2.SessionServiceClient
	organizationService             orgV2Beta.OrganizationServiceClient
	organizationServiceV2           orgV2.OrganizationServiceClient
	oidcService                     oidcV2Beta.OIDCServiceClient
	oidcServiceV2                   oidcV2.OIDCServiceClient
	featureV2                       featureV2.FeatureServiceClient
	userService                     userV2Beta.UserServiceClient
	userServiceV2                   userV2.UserServiceClient
	webkeyServiceV2                 webkeyV2.WebKeyServiceClient
	webkeyServiceV2Beta             webkeyV2Beta.WebKeyServiceClient
	appServiceV2Beta                appV2Beta.AppServiceClient
	telemetryServiceV2Beta          analyticsV2Beta.TelemetryServiceClient
	featureServiceV2                featureV2.FeatureServiceClient
	featureServiceV2Beta            featureV2Beta.FeatureServiceClient
	idpServiceV2                    idpV2.IdentityProviderServiceClient
	instanceServiceV2Beta           instanceV2Beta.InstanceServiceClient
	projectServiceV2Beta            projectV2Beta.ProjectServiceClient
	samlServiceV2                   samlV2.SAMLServiceClient
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

func (c *Client) ActionServiceV2Beta() actionV2Beta.ActionServiceClient {
	if c.actionServiceV2Beta == nil {
		c.actionServiceV2Beta = actionV2Beta.NewActionServiceClient(c.connection)
	}
	return c.actionServiceV2Beta
}

func (c *Client) AdminService() admin.AdminServiceClient {
	if c.adminService == nil {
		c.adminService = admin.NewAdminServiceClient(c.connection)
	}
	return c.adminService
}

func (c *Client) TelemetryServiceV2Beta() analyticsV2Beta.TelemetryServiceClient {
	if c.telemetryServiceV2Beta == nil {
		c.telemetryServiceV2Beta = analyticsV2Beta.NewTelemetryServiceClient(c.connection)
	}
	return c.telemetryServiceV2Beta
}

func (c *Client) AppServiceV2Beta() appV2Beta.AppServiceClient {
	if c.appServiceV2Beta == nil {
		c.appServiceV2Beta = appV2Beta.NewAppServiceClient(c.connection)
	}
	return c.appServiceV2Beta
}

func (c *Client) AuthService() auth.AuthServiceClient {
	if c.authService == nil {
		c.authService = auth.NewAuthServiceClient(c.connection)
	}
	return c.authService
}

func (c *Client) AuthorizationServiceV2Beta() authorizationV2Beta.AuthorizationServiceClient {
	if c.authorizationServiceV2Beta == nil {
		c.authorizationServiceV2Beta = authorizationV2Beta.NewAuthorizationServiceClient(c.connection)
	}
	return c.authorizationServiceV2Beta
}

func (c *Client) FeatureServiceV2() featureV2.FeatureServiceClient {
	if c.featureServiceV2 == nil {
		c.featureServiceV2 = featureV2.NewFeatureServiceClient(c.connection)
	}
	return c.featureServiceV2
}

func (c *Client) FeatureServiceV2Beta() featureV2Beta.FeatureServiceClient {
	if c.featureServiceV2Beta == nil {
		c.featureServiceV2Beta = featureV2Beta.NewFeatureServiceClient(c.connection)
	}
	return c.featureServiceV2Beta
}

func (c *Client) InstanceServiceV2Beta() instanceV2Beta.InstanceServiceClient {
	if c.instanceServiceV2Beta == nil {
		c.instanceServiceV2Beta = instanceV2Beta.NewInstanceServiceClient(c.connection)
	}
	return c.instanceServiceV2Beta
}

func (c *Client) InternalPermissionServiceV2Beta() internalPermissionV2Beta.InternalPermissionServiceClient {
	if c.internalPermissionServiceV2Beta == nil {
		c.internalPermissionServiceV2Beta = internalPermissionV2Beta.NewInternalPermissionServiceClient(c.connection)
	}
	return c.internalPermissionServiceV2Beta
}

func (c *Client) ManagementService() management.ManagementServiceClient {
	if c.managementService == nil {
		c.managementService = management.NewManagementServiceClient(c.connection)
	}
	return c.managementService
}

func (c *Client) IdpServiceV2() idpV2.IdentityProviderServiceClient {
	if c.idpServiceV2 == nil {
		c.idpServiceV2 = idpV2.NewIdentityProviderServiceClient(c.connection)
	}
	return c.idpServiceV2
}

func (c *Client) OIDCService() oidcV2Beta.OIDCServiceClient {
	if c.oidcService == nil {
		c.oidcService = oidcV2Beta.NewOIDCServiceClient(c.connection)
	}
	return c.oidcService
}

func (c *Client) OIDCServiceV2() oidcV2.OIDCServiceClient {
	if c.oidcServiceV2 == nil {
		c.oidcServiceV2 = oidcV2.NewOIDCServiceClient(c.connection)
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

func (c *Client) ProjectServiceV2Beta() projectV2Beta.ProjectServiceClient {
	if c.projectServiceV2Beta == nil {
		c.projectServiceV2Beta = projectV2Beta.NewProjectServiceClient(c.connection)
	}
	return c.projectServiceV2Beta
}

func (c *Client) SAMLServiceV2() samlV2.SAMLServiceClient {
	if c.samlServiceV2 == nil {
		c.samlServiceV2 = samlV2.NewSAMLServiceClient(c.connection)
	}
	return c.samlServiceV2
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

func (c *Client) SystemService() system.SystemServiceClient {
	if c.systemService == nil {
		c.systemService = system.NewSystemServiceClient(c.connection)
	}
	return c.systemService
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

func (c *Client) WebkeyServiceV2() webkeyV2.WebKeyServiceClient {
	if c.webkeyServiceV2 == nil {
		c.webkeyServiceV2 = webkeyV2.NewWebKeyServiceClient(c.connection)
	}
	return c.webkeyServiceV2
}

func (c *Client) WebkeyServiceV2Beta() webkeyV2Beta.WebKeyServiceClient {
	if c.webkeyServiceV2Beta == nil {
		c.webkeyServiceV2Beta = webkeyV2Beta.NewWebKeyServiceClient(c.connection)
	}
	return c.webkeyServiceV2Beta
}
