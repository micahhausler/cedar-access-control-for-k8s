package schema

// ModifyObjectMetaMaps modifies the ObjectMeta maps in the schema
//
// TODO: ENTITY TAGS: This is a hack until Cedar supports maps in the schema
func ModifyObjectMetaMaps(schema CedarSchema) {
	ns, ok := schema["meta::v1"]
	if !ok {
		return
	}
	keyValEntity := EntityShape{
		Type: "Record",
		Attributes: map[string]EntityAttribute{
			"key":   {Type: "String", Required: true},
			"value": {Type: "String", Required: false},
		},
	}
	ns.CommonTypes["KeyValue"] = keyValEntity

	keyValStringSliceEntity := EntityShape{
		Type: "Record",
		Attributes: map[string]EntityAttribute{
			"key":   {Type: "String", Required: true},
			"value": {Type: "Set", Element: &EntityAttributeElement{Type: "String"}, Required: false},
		},
	}
	ns.CommonTypes["KeyValueStringSlice"] = keyValStringSliceEntity

	schema["meta::v1"] = ns
}
