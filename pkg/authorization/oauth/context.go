package oauth

import "github.com/zitadel/oidc/v3/pkg/oidc"

// IntrospectionContext implements the [authorization.Ctx] interface with the [oidc.IntrospectionResponse] as underlying data.
type IntrospectionContext struct {
	oidc.IntrospectionResponse
}

// IsAuthorized implements [authorization.Ctx] by checking the `active` claim of the [oidc.IntrospectionResponse].
func (u *IntrospectionContext) IsAuthorized() bool {
	if u == nil {
		return false
	}
	return u.IntrospectionResponse.Active
}

// IsGrantedRole implements [authorization.Ctx] by checking if the `urn:zitadel:iam:org:project:roles` claim contains the requested role.
func (u *IntrospectionContext) IsGrantedRole(role string) bool {
	if u == nil {
		return false
	}
	return len(u.checkRoleClaim(role)) > 0
}

// IsGrantedRoleForOrganization implements [authorization.Ctx] by checking if the organizationID is part of the list
// of the `urn:zitadel:iam:org:project:roles` claim requested role.
func (u *IntrospectionContext) IsGrantedRoleForOrganization(role, organizationID string) bool {
	if u == nil {
		return false
	}
	_, ok := u.checkRoleClaim(role)[organizationID]
	return ok
}

func (u *IntrospectionContext) checkRoleClaim(role string) map[string]interface{} {
	roles, ok := u.IntrospectionResponse.Claims["urn:zitadel:iam:org:project:roles"].(map[string]interface{})
	if !ok || len(roles) == 0 {
		return nil
	}
	organisations, ok := roles[role].(map[string]interface{})
	if !ok {
		return nil
	}
	return organisations
}
