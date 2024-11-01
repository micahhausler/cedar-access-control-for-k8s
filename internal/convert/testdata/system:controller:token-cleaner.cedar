@roleBinding("system:controller:token-cleaner")
@role("system:controller:token-cleaner")
@policyRule("00")
@namespace("kube-system")
permit (
    principal is k8s::ServiceAccount,
    action in [k8s::Action::"delete", k8s::Action::"get", k8s::Action::"list", k8s::Action::"watch"],
    resource is k8s::Resource
)
when { principal.namespace == "kube-system" && principal.name == "token-cleaner" && resource.apiGroup == "" && resource.resource == "secrets" && resource has namespace && resource.namespace == "kube-system" };

@roleBinding("system:controller:token-cleaner")
@role("system:controller:token-cleaner")
@policyRule("01")
@namespace("kube-system")
permit (
    principal is k8s::ServiceAccount,
    action in [k8s::Action::"create", k8s::Action::"patch", k8s::Action::"update"],
    resource is k8s::Resource
)
when { principal.namespace == "kube-system" && principal.name == "token-cleaner" && ["", "events.k8s.io"].contains(resource.apiGroup) && resource.resource == "events" && resource has namespace && resource.namespace == "kube-system" };