package schema

func proxyOptionEntityShape() EntityShape {
	return EntityShape{
		Type: RecordType,
		Attributes: map[string]EntityAttribute{
			"kind":       {Type: StringType, Required: true},
			"apiVersion": {Type: StringType, Required: true},
			"path":       {Type: StringType, Required: true},
		},
	}
}

func NodeProxyOptions() Entity {
	return Entity{
		Annotations: docAnnotation("NodeProxyOptions represents options for proxying to a Kubernetes node"),
		Shape:       proxyOptionEntityShape(),
	}
}

func ServiceProxyOptions() Entity {
	return Entity{
		Annotations: docAnnotation("ServiceProxyOptions represents options for proxying to a Kubernetes service"),
		Shape:       proxyOptionEntityShape(),
	}
}

func PodProxyOptions() Entity {
	return Entity{
		Annotations: docAnnotation("PodProxyOptions represents options for proxying to a Kubernetes pod"),
		Shape:       proxyOptionEntityShape(),
	}
}

func PodPortForwardOptions() Entity {
	return Entity{
		Annotations: docAnnotation("PodPortForwardOptions represents options for port forwarding to a Kubernetes pod"),
		Shape: EntityShape{
			Type: RecordType,
			Attributes: map[string]EntityAttribute{
				"kind":       {Type: StringType, Required: true},
				"apiVersion": {Type: StringType, Required: true},
				"ports": {
					Type:     SetType,
					Required: false,
					Element: &EntityAttributeElement{
						Type: StringType,
					}},
			},
		},
	}
}

func podExecAttachEntityShape() EntityShape {
	return EntityShape{
		Type: RecordType,
		Attributes: map[string]EntityAttribute{
			"kind":       {Type: StringType, Required: true},
			"apiVersion": {Type: StringType, Required: true},
			"stdin":      {Type: BoolType, Required: true},
			"stdout":     {Type: BoolType, Required: true},
			"stderr":     {Type: BoolType, Required: true},
			"tty":        {Type: BoolType, Required: true},
			"container":  {Type: StringType, Required: true},
			"command": {Type: SetType, Required: true,
				Element: &EntityAttributeElement{
					Type: StringType,
				}},
		},
	}
}

func PodExecOptions() Entity {
	return Entity{
		Annotations: docAnnotation("PodExecOptions represents options for executing a command in a Kubernetes pod"),
		Shape:       podExecAttachEntityShape(),
	}
}

func PodAttachOptions() Entity {
	return Entity{
		Annotations: docAnnotation("PodAttachOptions represents options for attaching to a Kubernetes pod"),
		Shape:       podExecAttachEntityShape(),
	}
}

func AddConnectEntities(schema CedarSchema) {
	coreNSName := "core::v1"
	coreV1Ns, ok := schema[coreNSName]
	if !ok {
		coreV1Ns = CedarSchemaNamespace{}
	}
	coreV1EntityTypes := coreV1Ns.EntityTypes
	if coreV1Ns.EntityTypes == nil {
		coreV1EntityTypes = map[string]Entity{}
	}
	coreV1EntityTypes["NodeProxyOptions"] = NodeProxyOptions()
	coreV1EntityTypes["PodProxyOptions"] = PodProxyOptions()
	coreV1EntityTypes["PodPortForwardOptions"] = PodPortForwardOptions()
	coreV1EntityTypes["PodExecOptions"] = PodExecOptions()
	coreV1EntityTypes["PodAttachOptions"] = PodAttachOptions()
	coreV1EntityTypes["ServiceProxyOptions"] = ServiceProxyOptions()
	coreV1Ns.EntityTypes = coreV1EntityTypes
	schema[coreNSName] = coreV1Ns

	admissionNs, ok := schema["k8s::admission"]
	if !ok {
		admissionNs = CedarSchemaNamespace{}
	}
	actions := admissionNs.Actions
	if actions == nil {
		actions = map[string]ActionShape{}
	}
	actions[AdmissionConnectAction] = ActionShape{
		AppliesTo: ActionAppliesTo{
			PrincipalTypes: AdmissionPrincipalTypes("k8s"),
			ResourceTypes: []string{
				coreNSName + "::NodeProxyOptions",
				coreNSName + "::PodAttachOptions",
				coreNSName + "::PodExecOptions",
				coreNSName + "::PodPortForwardOptions",
				coreNSName + "::PodProxyOptions",
				coreNSName + "::ServiceProxyOptions",
			},
		},
		MemberOf: []ActionMember{{ID: AllAction}},
	}

}
