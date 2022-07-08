package zitadel

import "fmt"

const (
	scopeFormatProjectID = "urn:zitadel:iam:org:project:id:%s:aud"
)

//ScopeProjectID will add the requested projectID to the audience of the access and id token
func ScopeProjectID(projectID string) string {
	return fmt.Sprintf(scopeFormatProjectID, projectID)
}
