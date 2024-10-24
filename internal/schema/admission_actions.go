package schema

import (
	cedartypes "github.com/cedar-policy/cedar-go/types"
)

const (
	AdmissionCreateAction  = "create"
	AdmissionUpdateAction  = "update"
	AdmissionDeleteAction  = "delete"
	AdmissionConnectAction = "connect"
	AllAction              = "all"

	AdmissionActionEntityType = cedartypes.EntityType("k8s::admission::Action")
)

// AllAdmissionActions returns all the admission actions
func AllAdmissionActions() []string {
	return []string{AdmissionCreateAction, AdmissionUpdateAction, AdmissionDeleteAction, AdmissionConnectAction, AllAction}
}

// AddAdmissionActions adds all admission actions to a schema in the specified namespace
func AddAdmissionActions(schema CedarSchema, actionNamespace, principalNamespace string) {
	if actionNamespace == principalNamespace {
		principalNamespace = ""
	}
	namespacedPrincipalTypes := AdmissionPrincipalTypes(principalNamespace)

	for _, action := range AllAdmissionActions() {
		localActionShape := ActionShape{
			AppliesTo: ActionAppliesTo{
				PrincipalTypes: namespacedPrincipalTypes,
				ResourceTypes:  []string{},
			},
		}
		if action != AllAction {
			localActionShape.MemberOf = []ActionMember{{ID: AllAction}}
		}
		if ns, ok := schema[actionNamespace]; ok {
			if _, ok := ns.Actions[action]; !ok {
				ns.Actions[action] = localActionShape
			}
		} else {
			schema[actionNamespace] = CedarSchemaNamespace{
				Actions: map[string]ActionShape{action: localActionShape},
			}
		}
	}
}

// Adds the namespaced action to the schema
func AddResourceTypeToAction(schema CedarSchema, actionNamespace, action, resourceType string) {
	if ns, ok := schema[actionNamespace]; ok {
		if actionShape, ok := ns.Actions[action]; ok {
			actionShape.AppliesTo.ResourceTypes = append(actionShape.AppliesTo.ResourceTypes, resourceType)
			ns.Actions[action] = actionShape
		}
	}
}
