package schema

import (
	cedartypes "github.com/cedar-policy/cedar-go/types"
)

const (
	UserPrincipalType           = "User"
	GroupPrincipalType          = "Group"
	ServiceAccountPrincipalType = "ServiceAccount"
	NodePrincipalType           = "Node"
	ExtraValuesType             = "Extra"

	UserEntityType           = cedartypes.EntityType("k8s::" + UserPrincipalType)
	GroupEntityType          = cedartypes.EntityType("k8s::" + GroupPrincipalType)
	ExtraValuesEntityType    = cedartypes.EntityType("k8s::" + ExtraValuesType)
	ServiceAccountEntityType = cedartypes.EntityType("k8s::" + ServiceAccountPrincipalType)
	NodeEntityType           = cedartypes.EntityType("k8s::" + NodePrincipalType)
)

// UserEntity returns the Cedar schema entity for a user
func UserEntity() Entity {
	return Entity{
		MemberOfTypes: []string{GroupPrincipalType},
		Shape: EntityShape{
			Type: "Record",
			Attributes: map[string]EntityAttribute{
				"name":  {Type: "String", Required: true},
				"extra": {Type: "Set", Element: &EntityAttributeElement{Type: ExtraValuesType}},
			},
		},
	}
}

// GroupEntity returns the Cedar schema entity for a group
func GroupEntity() Entity {
	return Entity{
		Shape: EntityShape{Type: "Record", Attributes: map[string]EntityAttribute{}},
	}
}

// ServiceAccountEntity returns the Cedar schema entity for a service account
func ServiceAccountEntity() Entity {
	return Entity{
		MemberOfTypes: []string{GroupPrincipalType},
		Shape: EntityShape{
			Type: "Record",
			Attributes: map[string]EntityAttribute{
				"name":      {Type: "String", Required: true},
				"namespace": {Type: "String", Required: true},
				"extra":     {Type: "Set", Element: &EntityAttributeElement{Type: ExtraValuesType}},
			},
		},
	}
}

func NodeEntity() Entity {
	return Entity{
		MemberOfTypes: []string{GroupPrincipalType},
		Shape: EntityShape{
			Type: "Record",
			Attributes: map[string]EntityAttribute{
				"name":  {Type: "String", Required: true},
				"extra": {Type: "Set", Element: &EntityAttributeElement{Type: ExtraValuesType}},
			},
		},
	}
}

func ExtrasEntity() Entity {
	return Entity{
		MemberOfTypes: []string{},
		Shape: EntityShape{
			Type: "Record",
			Attributes: map[string]EntityAttribute{
				"key":    {Type: "String", Required: true},
				"values": {Type: "Set", Element: &EntityAttributeElement{Type: "String"}},
			},
		},
	}
}

// AddPrincipalsToSchema adds the user, group, and service account entities to the schema
func AddPrincipalsToSchema(schema CedarSchema, namespace string) {
	if _, ok := schema[namespace]; !ok {
		schema[namespace] = CedarSchemaNamespace{
			EntityTypes: map[string]Entity{},
			Actions:     map[string]ActionShape{},
			CommonTypes: map[string]EntityShape{},
		}
	}
	schema[namespace].EntityTypes[UserPrincipalType] = UserEntity()
	schema[namespace].EntityTypes[GroupPrincipalType] = GroupEntity()
	schema[namespace].EntityTypes[ServiceAccountPrincipalType] = ServiceAccountEntity()
	schema[namespace].EntityTypes[NodePrincipalType] = NodeEntity()
	schema[namespace].EntityTypes[ExtraValuesType] = ExtrasEntity()
}

// AdmissionPrincipalTypes returns the list of principal types from the
// specified namespace that can be used in admission decisions
func AdmissionPrincipalTypes(namespace string) []string {
	return AuthorizationPrincipalTypes(namespace)
}

// AuthorizationPrincipalTypes returns the list of principal types from the
// specified namespace that can be used in authorization decisions
func AuthorizationPrincipalTypes(namespace string) []string {
	k8sPrincipals := []string{UserPrincipalType, GroupPrincipalType, ServiceAccountPrincipalType, NodePrincipalType}
	if namespace == "" {
		return k8sPrincipals
	}
	resp := make([]string, len(k8sPrincipals))
	for i, principal := range k8sPrincipals {
		resp[i] = namespace + "::" + principal
	}
	return resp
}
