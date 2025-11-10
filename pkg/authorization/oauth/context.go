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

// OrganizationID implements [authorization.Ctx] by returning the `urn:zitadel:iam:user:resourceowner:id` claim
// of the [oidc.IntrospectionResponse].
func (c *IntrospectionContext) OrganizationID() string {
	if c == nil {
		return ""
	}
	// check for organization ID when using scope "urn:zitadel:iam:user:resourceowner"
	orgID, _ := c.IntrospectionResponse.Claims["urn:zitadel:iam:user:resourceowner:id"].(string)
	return orgID
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

// IsGrantedRoleInProject checks if the role is granted in the specified project using the
// `urn:zitadel:iam:org:project:{projectId}:roles` claim format. This is the recommended format
// per Zitadel's latest standards.
func (c *IntrospectionContext) IsGrantedRoleInProject(projectID, role string) bool {
	if c == nil {
		return false
	}
	organisations := c.checkProjectRoleClaim(projectID, role)
	return len(organisations) > 0
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

func (c *IntrospectionContext) checkProjectRoleClaim(projectID, role string) map[string]interface{} {
	claimKey := "urn:zitadel:iam:org:project:" + projectID + ":roles"
	roles, ok := c.IntrospectionResponse.Claims[claimKey].(map[string]interface{})
	if !ok || len(roles) == 0 {
		return nil
	}
	organisations, ok := roles[role].(map[string]interface{})
	if !ok {
		return nil
	}
	return organisations
}
