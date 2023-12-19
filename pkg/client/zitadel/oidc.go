package zitadel

import "fmt"

const (
	scopeFormatProjectID  = "urn:zitadel:iam:org:project:id:%s:aud"
	scopeZITADELProjectID = "zitadel"
)

// ScopeProjectID will add the requested projectID to the audience of the access and id token
// deprecated: use [client.ScopeProjectID]
func ScopeProjectID(projectID string) string {
	return fmt.Sprintf(scopeFormatProjectID, projectID)
}

// ScopeZitadelAPI adds the ProjectID of the ZITADEL Project
// deprecated: use [client.ScopeZitadelAPI]
func ScopeZitadelAPI() string {
	return ScopeProjectID(scopeZITADELProjectID)
}
