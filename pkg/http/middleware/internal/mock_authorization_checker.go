// Package internal provides internal test utilities for the middleware package.
package internal

import (
	"context"

	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
)

// MockAuthorizationChecker is a mock implementation of authorization.AuthorizationChecker
// for testing purposes. It returns pre-configured contexts and errors.
type MockAuthorizationChecker struct {
	Ctx *MockAuthContext
	Err error
}

// CheckAuthorization returns the pre-configured context or error.
// The parameters are intentionally unused as this is a test mock.
func (m *MockAuthorizationChecker) CheckAuthorization(_ context.Context, _ string, _ ...authorization.CheckOption) (*MockAuthContext, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	return m.Ctx, nil
}

// MockAuthContext is a mock implementation of authorization.Ctx for testing purposes.
// It stores user and organization information and tracks role grants.
type MockAuthContext struct {
	id    string
	orgID string
	token string
	roles map[string]bool
}

// NewMockAuthContext creates a new MockAuthContext with the specified user and organization IDs.
func NewMockAuthContext(userID, organizationID string) *MockAuthContext {
	return &MockAuthContext{
		id:    userID,
		orgID: organizationID,
	}
}

// NewMockAuthContextWithRoles creates a new MockAuthContext with roles.
func NewMockAuthContextWithRoles(userID string, roles map[string]bool) *MockAuthContext {
	return &MockAuthContext{
		id:    userID,
		roles: roles,
	}
}

// SetToken sets the authorization token.
func (m *MockAuthContext) SetToken(token string) {
	m.token = token
}

// GetToken returns the authorization token.
func (m *MockAuthContext) GetToken() string {
	return m.token
}

// IsAuthorized returns true if the context is not nil.
func (m *MockAuthContext) IsAuthorized() bool {
	return m != nil
}

// OrganizationID returns the organization ID.
func (m *MockAuthContext) OrganizationID() string {
	if m == nil {
		return ""
	}
	return m.orgID
}

// UserID returns the user ID.
func (m *MockAuthContext) UserID() string {
	if m == nil {
		return ""
	}
	return m.id
}

// IsGrantedRole checks if the given role is granted.
func (m *MockAuthContext) IsGrantedRole(role string) bool {
	if m == nil || m.roles == nil {
		return false
	}
	return m.roles[role]
}

// IsGrantedRoleInOrganization always returns false in this mock implementation.
func (m *MockAuthContext) IsGrantedRoleInOrganization(_, _ string) bool {
	return false
}

// IsGrantedRoleInProject always returns false in this mock implementation.
func (m *MockAuthContext) IsGrantedRoleInProject(_, _, _ string) bool {
	return false
}
