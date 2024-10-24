@clusterRoleBinding("system:controller:horizontal-pod-autoscaler")
@clusterRole("system:controller:horizontal-pod-autoscaler")
@policyRule("00")
permit (
  principal is k8s::ServiceAccount,
  action in [k8s::Action::"get", k8s::Action::"list", k8s::Action::"watch"],
  resource is k8s::Resource
)
when
{
  principal.namespace == "kube-system" &&
  principal.name == "horizontal-pod-autoscaler" &&
  resource.apiGroup == "autoscaling" &&
  resource.resource == "horizontalpodautoscalers"
};

@clusterRoleBinding("system:controller:horizontal-pod-autoscaler")
@clusterRole("system:controller:horizontal-pod-autoscaler")
@policyRule("01")
permit (
  principal is k8s::ServiceAccount,
  action == k8s::Action::"horizontalpodautoscalers/status",
  resource is k8s::Resource
)
when
{
  principal.namespace == "kube-system" &&
  principal.name == "horizontal-pod-autoscaler" &&
  resource.apiGroup == "autoscaling" &&
  resource.resource == "update"
};

@clusterRoleBinding("system:controller:horizontal-pod-autoscaler")
@clusterRole("system:controller:horizontal-pod-autoscaler")
@policyRule("02")
permit (
  principal is k8s::ServiceAccount,
  action in [k8s::Action::"get", k8s::Action::"update"],
  resource is k8s::Resource
)
when
{
  principal.namespace == "kube-system" &&
  principal.name == "horizontal-pod-autoscaler" &&
  resource has subresource &&
  resource.subresource == "scale"
};

@clusterRoleBinding("system:controller:horizontal-pod-autoscaler")
@clusterRole("system:controller:horizontal-pod-autoscaler")
@policyRule("03")
permit (
  principal is k8s::ServiceAccount,
  action == k8s::Action::"get",
  resource is k8s::Resource
)
when
{
  principal.namespace == "kube-system" &&
  principal.name == "horizontal-pod-autoscaler" &&
  resource.apiGroup == "" &&
  (resource.resource == "nodes" ||
   resource.resource == "pods" &&
   resource has subresource &&
   resource.subresource != "")
};

@clusterRoleBinding("system:controller:horizontal-pod-autoscaler")
@clusterRole("system:controller:horizontal-pod-autoscaler")
@policyRule("04")
permit (
  principal is k8s::ServiceAccount,
  action == k8s::Action::"list",
  resource is k8s::Resource
)
when
{
  principal.namespace == "kube-system" &&
  principal.name == "horizontal-pod-autoscaler" &&
  resource.apiGroup == "" &&
  resource.resource == "pods"
};

@clusterRoleBinding("system:controller:horizontal-pod-autoscaler")
@clusterRole("system:controller:horizontal-pod-autoscaler")
@policyRule("05")
permit (
  principal is k8s::ServiceAccount,
  action == k8s::Action::"list",
  resource is k8s::Resource
)
when
{
  principal.namespace == "kube-system" &&
  principal.name == "horizontal-pod-autoscaler" &&
  resource.apiGroup == "metrics.k8s.io" &&
  resource.resource == "pods"
};

@clusterRoleBinding("system:controller:horizontal-pod-autoscaler")
@clusterRole("system:controller:horizontal-pod-autoscaler")
@policyRule("06")
permit (
  principal is k8s::ServiceAccount,
  action in [k8s::Action::"get", k8s::Action::"list"],
  resource is k8s::Resource
)
when
{
  principal.namespace == "kube-system" &&
  principal.name == "horizontal-pod-autoscaler" &&
  resource.apiGroup == "custom.metrics.k8s.io"
};

@clusterRoleBinding("system:controller:horizontal-pod-autoscaler")
@clusterRole("system:controller:horizontal-pod-autoscaler")
@policyRule("07")
permit (
  principal is k8s::ServiceAccount,
  action in [k8s::Action::"get", k8s::Action::"list"],
  resource is k8s::Resource
)
when
{
  principal.namespace == "kube-system" &&
  principal.name == "horizontal-pod-autoscaler" &&
  resource.apiGroup == "external.metrics.k8s.io"
};

@clusterRoleBinding("system:controller:horizontal-pod-autoscaler")
@clusterRole("system:controller:horizontal-pod-autoscaler")
@policyRule("08")
permit (
  principal is k8s::ServiceAccount,
  action in
    [k8s::Action::"create", k8s::Action::"patch", k8s::Action::"update"],
  resource is k8s::Resource
)
when
{
  principal.namespace == "kube-system" &&
  principal.name == "horizontal-pod-autoscaler" &&
  ["", "events.k8s.io"].contains(resource.apiGroup) &&
  resource.resource == "events"
};
