package oauth

import "github.com/zitadel/oidc/v3/pkg/oidc"

// IntrospectionContext implements the [authorization.Ctx] interface with the [oidc.IntrospectionResponse] as underlying data.
type IntrospectionContext struct {
	oidc.IntrospectionResponse
	token string
}

// IsAuthorized implements [authorization.Ctx] by checking the `active` claim of the [oidc.IntrospectionResponse].
func (c *IntrospectionContext) IsAuthorized() bool {
	if c == nil {
		return false
	}
	return c.IntrospectionResponse.Active
}

// UserID implements [authorization.Ctx] by returning the `sub` claim of the [oidc.IntrospectionResponse].
func (c *IntrospectionContext) UserID() string {
	if c == nil {
		return ""
	}
	return c.IntrospectionResponse.Subject
}

// IsGrantedRole implements [authorization.Ctx] by checking if the `urn:zitadel:iam:org:project:roles` claim contains the requested role.
func (c *IntrospectionContext) IsGrantedRole(role string) bool {
	if c == nil {
		return false
	}
	return len(c.checkRoleClaim(role)) > 0
}

// IsGrantedRoleInOrganization implements [authorization.Ctx] by checking if the organizationID is part of the list
// of the `urn:zitadel:iam:org:project:roles` claim requested role.
func (c *IntrospectionContext) IsGrantedRoleInOrganization(role, organizationID string) bool {
	if c == nil {
		return false
	}
	_, ok := c.checkRoleClaim(role)[organizationID]
	return ok
}

func (c *IntrospectionContext) SetToken(token string) {
	c.token = token
}

func (c *IntrospectionContext) GetToken() string {
	return c.token
}

func (c *IntrospectionContext) checkRoleClaim(role string) map[string]interface{} {
	roles, ok := c.IntrospectionResponse.Claims["urn:zitadel:iam:org:project:roles"].(map[string]interface{})
	if !ok || len(roles) == 0 {
		return nil
	}
	organisations, ok := roles[role].(map[string]interface{})
	if !ok {
		return nil
	}
	return organisations
}
