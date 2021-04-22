package zitadel

import "fmt"

const (
	//ProjectID of the ZITADEL Project on zitadel.ch
	ProjectID = "69234237810729019"

	scopeFormatProjectID = "urn:zitadel:iam:org:project:id:%s:aud"
)

//ScopeProjectID will add the requested projectID to the audience of the access and id token
func ScopeProjectID(projectID string) string {
	return fmt.Sprintf(scopeFormatProjectID, projectID)
}

//ScopeZitadelAPI adds the ProjectID of the ZITADEL Project on zitadel.ch
func ScopeZitadelAPI() string {
	return ScopeProjectID(ProjectID)
}
