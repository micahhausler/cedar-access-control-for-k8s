package schema

import (
	"testing"
)

func TestGetEntityShape(t *testing.T) {
	schema := NewCedarSchema()
	AddPrincipalsToSchema(schema, "")
	authZNs := CedarSchemaNamespace{
		EntityTypes: map[string]Entity{
			"Resource": ResourceEntity(),
		},
		CommonTypes: map[string]EntityShape{},
	}
	schema["authorization"] = authZNs

	cases := []struct {
		name       string
		schema     CedarSchema
		entityType string
		expected   bool
	}{
		{
			name:       "exists in empty namespace",
			schema:     schema,
			entityType: "User",
			expected:   true,
		},
		{
			name:       "authorization namespace",
			schema:     schema,
			entityType: "authorization::Resource",
			expected:   true,
		},
		{
			name:       "non-existent entity with non-nil common types",
			schema:     schema,
			entityType: "authorization::NonResourceURL",
			expected:   false,
		},
		{
			name:       "non-existent entity with nil common types",
			schema:     schema,
			entityType: "Lambda",
			expected:   false,
		},
		{
			name:       "empty schema",
			schema:     nil,
			entityType: "User",
			expected:   false,
		},
		{
			name:       "no namespace",
			schema:     NewCedarSchema(),
			entityType: "User",
			expected:   false,
		},
		{
			name: "no entity or common types",
			schema: CedarSchema{"test": CedarSchemaNamespace{
				EntityTypes: nil,
				CommonTypes: nil,
			}},
			entityType: "test::Resource",
			expected:   false,
		},
		{
			name: "common type",
			schema: CedarSchema{
				"test": CedarSchemaNamespace{
					CommonTypes: map[string]EntityShape{
						"FieldRequirement": FieldRequirementEntityShape(),
					},
				},
			},
			entityType: "test::FieldRequirement",
			expected:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := tc.schema.GetEntityShape(tc.entityType)
			if got != tc.expected {
				t.Errorf("Unexpected result for GetEntityShape() = %v, wanted %v", got, tc.expected)
			}

		})
	}

}
