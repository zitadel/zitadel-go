package oauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestIntrospectionContext_IsGrantedRoleInProject(t *testing.T) {
	tests := []struct {
		name           string
		ctx            *IntrospectionContext
		projectID      string
		role           string
		organizationID string
		want           bool
	}{
		{
			name:           "nil context",
			ctx:            nil,
			projectID:      "my_project",
			role:           "create",
			organizationID: "",
			want:           false,
		},
		{
			name: "project claim does not exist",
			ctx: &IntrospectionContext{
				IntrospectionResponse: oidc.IntrospectionResponse{
					Active: true,
					Claims: map[string]interface{}{},
				},
			},
			projectID:      "my_project",
			role:           "create",
			organizationID: "",
			want:           false,
		},
		{
			name: "project claim exists but role does not exist",
			ctx: &IntrospectionContext{
				IntrospectionResponse: oidc.IntrospectionResponse{
					Active: true,
					Claims: map[string]interface{}{
						"urn:zitadel:iam:org:project:my_project:roles": map[string]interface{}{
							"read": map[string]interface{}{
								"302802686149969770": "zitadel_domain.com",
							},
						},
					},
				},
			},
			projectID:      "my_project",
			role:           "create",
			organizationID: "",
			want:           false,
		},
		{
			name: "role exists in project with organizations",
			ctx: &IntrospectionContext{
				IntrospectionResponse: oidc.IntrospectionResponse{
					Active: true,
					Claims: map[string]interface{}{
						"urn:zitadel:iam:org:project:my_project:roles": map[string]interface{}{
							"create": map[string]interface{}{
								"302802686149969770": "zitadel_domain.com",
							},
							"read": map[string]interface{}{
								"302802686149969770": "zitadel_domain.com",
							},
						},
					},
				},
			},
			projectID:      "my_project",
			role:           "create",
			organizationID: "",
			want:           true,
		},
		{
			name: "role exists in project within given organization",
			ctx: &IntrospectionContext{
				IntrospectionResponse: oidc.IntrospectionResponse{
					Active: true,
					Claims: map[string]interface{}{
						"urn:zitadel:iam:org:project:my_project:roles": map[string]interface{}{
							"create": map[string]interface{}{
								"302802686149969770": "zitadel_domain.com",
							},
							"read": map[string]interface{}{
								"302802686149969770": "zitadel_domain.com",
							},
						},
					},
				},
			},
			projectID:      "my_project",
			role:           "create",
			organizationID: "302802686149969770",
			want:           true,
		},
		{
			name: "role exists in project within unknown organization",
			ctx: &IntrospectionContext{
				IntrospectionResponse: oidc.IntrospectionResponse{
					Active: true,
					Claims: map[string]interface{}{
						"urn:zitadel:iam:org:project:my_project:roles": map[string]interface{}{
							"create": map[string]interface{}{
								"302802686149969770": "zitadel_domain.com",
							},
							"read": map[string]interface{}{
								"302802686149969770": "zitadel_domain.com",
							},
						},
					},
				},
			},
			projectID:      "my_project",
			role:           "create",
			organizationID: "totallyrealorganizationid",
			want:           false,
		},
		{
			name: "role exists in project with multiple organizations",
			ctx: &IntrospectionContext{
				IntrospectionResponse: oidc.IntrospectionResponse{
					Active: true,
					Claims: map[string]interface{}{
						"urn:zitadel:iam:org:project:my_project:roles": map[string]interface{}{
							"create": map[string]interface{}{
								"302802686149969770": "zitadel_domain.com",
								"302802686149969771": "another-org.example.com",
							},
						},
					},
				},
			},
			projectID:      "my_project",
			role:           "create",
			organizationID: "",
			want:           true,
		},
		{
			name: "role exists but with empty organizations map",
			ctx: &IntrospectionContext{
				IntrospectionResponse: oidc.IntrospectionResponse{
					Active: true,
					Claims: map[string]interface{}{
						"urn:zitadel:iam:org:project:my_project:roles": map[string]interface{}{
							"create": map[string]interface{}{},
						},
					},
				},
			},
			projectID:      "my_project",
			role:           "create",
			organizationID: "",
			want:           false,
		},
		{
			name: "different project, same role name",
			ctx: &IntrospectionContext{
				IntrospectionResponse: oidc.IntrospectionResponse{
					Active: true,
					Claims: map[string]interface{}{
						"urn:zitadel:iam:org:project:my_project:roles": map[string]interface{}{
							"create": map[string]interface{}{
								"302802686149969770": "zitadel_domain.com",
							},
						},
						"urn:zitadel:iam:org:project:another-project:roles": map[string]interface{}{
							"create": map[string]interface{}{
								"302802686149969770": "zitadel_domain.com",
							},
						},
					},
				},
			},
			projectID:      "another-project",
			role:           "create",
			organizationID: "",
			want:           true,
		},
		{
			name: "wrong project ID",
			ctx: &IntrospectionContext{
				IntrospectionResponse: oidc.IntrospectionResponse{
					Active: true,
					Claims: map[string]interface{}{
						"urn:zitadel:iam:org:project:my_project:roles": map[string]interface{}{
							"create": map[string]interface{}{
								"302802686149969770": "zitadel_domain.com",
							},
						},
					},
				},
			},
			projectID:      "wrong-project",
			role:           "create",
			organizationID: "",
			want:           false,
		},
		{
			name: "project claim is not a map",
			ctx: &IntrospectionContext{
				IntrospectionResponse: oidc.IntrospectionResponse{
					Active: true,
					Claims: map[string]interface{}{
						"urn:zitadel:iam:org:project:my_project:roles": "not-a-map",
					},
				},
			},
			projectID:      "my_project",
			role:           "create",
			organizationID: "",
			want:           false,
		},
		{
			name: "role value is not a map",
			ctx: &IntrospectionContext{
				IntrospectionResponse: oidc.IntrospectionResponse{
					Active: true,
					Claims: map[string]interface{}{
						"urn:zitadel:iam:org:project:my_project:roles": map[string]interface{}{
							"create": "not-a-map",
						},
					},
				},
			},
			projectID:      "my_project",
			role:           "create",
			organizationID: "",
			want:           false,
		},
		{
			name: "read role from example JWT payload",
			ctx: &IntrospectionContext{
				IntrospectionResponse: oidc.IntrospectionResponse{
					Active: true,
					Claims: map[string]interface{}{
						"urn:zitadel:iam:org:project:my_project:roles": map[string]interface{}{
							"create": map[string]interface{}{
								"302802686149969770": "zitadel_domain.com",
							},
							"read": map[string]interface{}{
								"302802686149969770": "zitadel_domain.com",
							},
						},
					},
				},
			},
			projectID:      "my_project",
			role:           "read",
			organizationID: "",
			want:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ctx.IsGrantedRoleInProject(tt.projectID, tt.role, tt.organizationID)
			assert.Equal(t, tt.want, got)
		})
	}
}
