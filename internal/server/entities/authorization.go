package entities

import (
	"fmt"

	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// ResourceRequestToPath returns a Kubernetes URL for a given authorization attribute
//
// This function does not implement field and label selectors in the URl, since
// we never add both a filtered request and an unfiltered request in the entity list
func ResourceRequestToPath(attributes authorizer.Attributes) string {
	base := "/api"
	if attributes.GetAPIGroup() != "" {
		base = "/apis/" + attributes.GetAPIGroup()
	}
	namespace := ""
	if attributes.GetNamespace() != "" {
		namespace = "/namespaces/" + attributes.GetNamespace()
	}
	resp := fmt.Sprintf("%s/%s%s/%s", base, attributes.GetAPIVersion(), namespace, attributes.GetResource())
	if attributes.GetName() != "" {
		resp = resp + "/" + attributes.GetName()
	}
	if attributes.GetSubresource() != "" {
		resp = resp + "/" + attributes.GetSubresource()
	}
	return resp
}
