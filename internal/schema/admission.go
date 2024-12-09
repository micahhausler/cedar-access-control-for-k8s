package schema

import cedartypes "github.com/cedar-policy/cedar-go/types"

const (
	MetaV1KeyValueEntity  = cedartypes.EntityType("meta::v1::KeyValue")
	MetaV1KeyValuesEntity = cedartypes.EntityType("meta::v1::KeyValues")
)

// ModifyObjectMetaMaps modifies the ObjectMeta maps in the schema
func ModifyObjectMetaMaps(schema CedarSchema) {
	ns, ok := schema["meta::v1"]
	if !ok {
		return
	}
	ns.EntityTypes["KeyValue"] = Entity{
		MemberOfTypes: []string{},
		Shape: EntityShape{
			Type:       RecordType,
			Attributes: map[string]EntityAttribute{},
		},
		Tags: &Tags{Type: StringType},
	}
	ns.EntityTypes["KeyValues"] = Entity{
		MemberOfTypes: []string{},
		Shape: EntityShape{
			Type:       RecordType,
			Attributes: map[string]EntityAttribute{},
		},
		Tags: &Tags{Type: SetType, Element: &EntityAttributeElement{Type: StringType}},
	}
	schema["meta::v1"] = ns
}
