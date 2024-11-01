@clusterRoleBinding("system:kube-controller-manager")
@clusterRole("system:kube-controller-manager")
@policyRule("00")
permit (
    principal is k8s::User,
    action in [k8s::Action::"list", k8s::Action::"watch"],
    resource is k8s::Resource
)
when { principal.name == "system:kube-controller-manager" };

@clusterRoleBinding("system:kube-controller-manager")
@clusterRole("system:kube-controller-manager")
@policyRule("01")
permit (
    principal is k8s::User,
    action == k8s::Action::"create",
    resource is k8s::Resource
)
when { principal.name == "system:kube-controller-manager" && resource.apiGroup == "" && resource.resource == "servicaccount" && resource has subresource && resource.subresource == "token" };