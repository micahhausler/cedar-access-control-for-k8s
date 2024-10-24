@clusterRoleBinding("system:node-proxier")
@clusterRole("system:node-proxier")
@policyRule("00")
permit (
  principal is k8s::User,
  action in [k8s::Action::"list", k8s::Action::"watch"],
  resource is k8s::Resource
)
when
{
  principal.name == "system:kube-proxy" &&
  resource.apiGroup == "" &&
  ["endpoints", "services"].contains(resource.resource)
};

@clusterRoleBinding("system:node-proxier")
@clusterRole("system:node-proxier")
@policyRule("01")
permit (
  principal is k8s::User,
  action in [k8s::Action::"get", k8s::Action::"list", k8s::Action::"watch"],
  resource is k8s::Resource
)
when
{
  principal.name == "system:kube-proxy" &&
  resource.apiGroup == "" &&
  resource.resource == "nodes"
};

@clusterRoleBinding("system:node-proxier")
@clusterRole("system:node-proxier")
@policyRule("02")
permit (
  principal is k8s::User,
  action in
    [k8s::Action::"create", k8s::Action::"patch", k8s::Action::"update"],
  resource is k8s::Resource
)
when
{
  principal.name == "system:kube-proxy" &&
  ["", "events.k8s.io"].contains(resource.apiGroup) &&
  resource.resource == "events"
};

@clusterRoleBinding("system:node-proxier")
@clusterRole("system:node-proxier")
@policyRule("03")
permit (
  principal is k8s::User,
  action in [k8s::Action::"list", k8s::Action::"watch"],
  resource is k8s::Resource
)
when
{
  principal.name == "system:kube-proxy" &&
  resource.apiGroup == "discovery.k8s.io" &&
  resource.resource == "endpointslices"
};
