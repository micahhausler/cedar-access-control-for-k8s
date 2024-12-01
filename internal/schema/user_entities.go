package schema

import (
	cedartypes "github.com/cedar-policy/cedar-go/types"
)

const (
	UserPrincipalType           = "User"
	GroupPrincipalType          = "Group"
	ServiceAccountPrincipalType = "ServiceAccount"
	NodePrincipalType           = "Node"
	ExtraValueType              = "Extra"
	ExtraValuesAttributeType    = "ExtraAttribute"

	UserEntityType           = cedartypes.EntityType("k8s::" + UserPrincipalType)
	GroupEntityType          = cedartypes.EntityType("k8s::" + GroupPrincipalType)
	ExtraValueEntityType     = cedartypes.EntityType("k8s::" + ExtraValueType)
	ServiceAccountEntityType = cedartypes.EntityType("k8s::" + ServiceAccountPrincipalType)
	NodeEntityType           = cedartypes.EntityType("k8s::" + NodePrincipalType)
)

// UserEntity returns the Cedar schema entity for a user
func UserEntity() Entity {
	return Entity{
		MemberOfTypes: []string{GroupPrincipalType},
		Shape: EntityShape{
			Type: RecordType,
			Attributes: map[string]EntityAttribute{
				"name": {Type: StringType, Required: true},
				"extra": {
					Type:     SetType,
					Required: false,
					Element: &EntityAttributeElement{
						Type: ExtraValuesAttributeType,
					}},
			},
		},
	}
}

// GroupEntity returns the Cedar schema entity for a group
func GroupEntity() Entity {
	return Entity{
		Shape: EntityShape{Type: RecordType, Attributes: map[string]EntityAttribute{
			"name": {Type: StringType, Required: true},
		}},
	}
}

// ServiceAccountEntity returns the Cedar schema entity for a service account
func ServiceAccountEntity() Entity {
	return Entity{
		MemberOfTypes: []string{GroupPrincipalType},
		Shape: EntityShape{
			Type: RecordType,
			Attributes: map[string]EntityAttribute{
				"name":      {Type: StringType, Required: true},
				"namespace": {Type: StringType, Required: true},
				"extra": {
					Type:     SetType,
					Required: false,
					Element: &EntityAttributeElement{
						Type: ExtraValuesAttributeType,
					}},
			},
		},
	}
}

func NodeEntity() Entity {
	return Entity{
		MemberOfTypes: []string{GroupPrincipalType},
		Shape: EntityShape{
			Type: RecordType,
			Attributes: map[string]EntityAttribute{
				"name": {Type: StringType, Required: true},
				"extra": {
					Type:     SetType,
					Required: false,
					Element: &EntityAttributeElement{
						Type: ExtraValuesAttributeType,
					}},
			},
		},
	}
}

// TODO: ENTITY TAGS: this is just here until we get real key/value map support
func ExtraEntityShape() EntityShape {
	return EntityShape{
		Type: RecordType,
		Attributes: map[string]EntityAttribute{
			"key":    {Type: StringType, Required: true},
			"values": {Type: SetType, Required: true, Element: &EntityAttributeElement{Type: StringType}},
		},
	}
}

// TODO: ENTITY TAGS: this is just here until we get real key/value map support
func ExtraEntity() Entity {
	return Entity{
		MemberOfTypes: []string{},
		Shape: EntityShape{
			Type: RecordType,
			Attributes: map[string]EntityAttribute{
				"key": {Type: StringType, Required: true},
				// Kube-API sends a SAR for each individual value with a given key
				// SAR's resource name is not a required field, which is where a value
				// is encoded, so value cannot be a required field.
				"value": {Type: StringType, Required: false},
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
	schema[namespace].EntityTypes[ExtraValueType] = ExtraEntity()
	schema[namespace].CommonTypes[ExtraValuesAttributeType] = ExtraEntityShape()
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
