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
		Annotations:   docAnnotation("User represents a Kubernetes user identity"),
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
		Annotations: docAnnotation("Group represents a Kubernetes group"),
		Shape: EntityShape{Type: RecordType, Attributes: map[string]EntityAttribute{
			"name": {Type: StringType, Required: true},
		}},
	}
}

// ServiceAccountEntity returns the Cedar schema entity for a service account
func ServiceAccountEntity() Entity {
	return Entity{
		Annotations:   docAnnotation("ServiceAccount represents a Kubernetes service account identity"),
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
		Annotations:   docAnnotation("Node represents a Kubernetes node identity"),
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

func ExtraEntityShape() EntityShape {
	return EntityShape{
		Annotations: docAnnotation("ExtraAttribute represents a set of key-value pairs for an identity"),
		Type:        RecordType,
		Attributes: map[string]EntityAttribute{
			"key":    {Type: StringType, Required: true},
			"values": {Type: SetType, Required: true, Element: &EntityAttributeElement{Type: StringType}},
		},
	}
}

func ExtraEntity() Entity {
	return Entity{
		Annotations:   docAnnotation("Extra represents a set of key-value pairs for an identity"),
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
	ns, ok := schema[namespace]
	if !ok {
		schema[namespace] = CedarSchemaNamespace{
			EntityTypes: map[string]Entity{},
			Actions:     map[string]ActionShape{},
			CommonTypes: map[string]EntityShape{},
		}
	}
	ns.Annotations = docAnnotation("Kubernetes Authorization namespace")
	ns.EntityTypes[UserPrincipalType] = UserEntity()
	ns.EntityTypes[GroupPrincipalType] = GroupEntity()
	ns.EntityTypes[ServiceAccountPrincipalType] = ServiceAccountEntity()
	ns.EntityTypes[NodePrincipalType] = NodeEntity()
	ns.EntityTypes[ExtraValueType] = ExtraEntity()
	ns.CommonTypes[ExtraValuesAttributeType] = ExtraEntityShape()
	schema[namespace] = ns
}

// AdmissionPrincipalTypes returns the list of principal types from the
// specified namespace that can be used in admission decisions
func AdmissionPrincipalTypes(namespace string) []string {
	return AuthorizationPrincipalTypes(namespace)
}

// AuthorizationPrincipalTypes returns the list of principal types from the
// specified namespace that can be used in authorization decisions
func AuthorizationPrincipalTypes(namespace string) []string {
	k8sPrincipals := []string{
		UserPrincipalType,
		GroupPrincipalType,
		ServiceAccountPrincipalType,
		NodePrincipalType,
	}
	if namespace == "" {
		return k8sPrincipals
	}
	resp := make([]string, len(k8sPrincipals))
	for i, principal := range k8sPrincipals {
		resp[i] = namespace + "::" + principal
	}
	return resp
}
