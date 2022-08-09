package zitadel

import "fmt"

const (
	scopeFormatProjectID  = "urn:zitadel:iam:org:project:id:%s:aud"
	scopeZITADELProjectID = "zitadel"
)

//ScopeProjectID will add the requested projectID to the audience of the access and id token
func ScopeProjectID(projectID string) string {
	return fmt.Sprintf(scopeFormatProjectID, projectID)
}

//ScopeZitadelAPI adds the ProjectID of the ZITADEL Project
func ScopeZitadelAPI() string {
	return ScopeProjectID(scopeZITADELProjectID)
}
