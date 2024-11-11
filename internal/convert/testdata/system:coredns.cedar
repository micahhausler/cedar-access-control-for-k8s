@clusterRoleBinding("system:coredns")
@clusterRole("system:coredns")
@policyRule("00")
permit (
  principal is k8s::ServiceAccount,
  action in [k8s::Action::"list", k8s::Action::"watch"],
  resource is k8s::Resource
)
when
{
  principal.namespace == "kube-system" &&
  principal.name == "coredns" &&
  resource.apiGroup == "" &&
  ["endpoints", "services", "pods", "namespaces"].contains(resource.resource)
}
unless { resource has subresource };

@clusterRoleBinding("system:coredns")
@clusterRole("system:coredns")
@policyRule("01")
permit (
  principal is k8s::ServiceAccount,
  action in [k8s::Action::"list", k8s::Action::"watch"],
  resource is k8s::Resource
)
when
{
  principal.namespace == "kube-system" &&
  principal.name == "coredns" &&
  resource.apiGroup == "discovery.k8s.io" &&
  resource.resource == "endpointslices"
}
unless { resource has subresource };
