@clusterRoleBinding("crazy-policy")
@clusterRole("crazy-policy")
@policyRule("00")
permit (
  principal is k8s::ServiceAccount,
  action in [k8s::Action::"get", k8s::Action::"list", k8s::Action::"watch"],
  resource is k8s::Resource
)
when
{
  principal.namespace == "default" &&
  principal.name == "crazy-service-account" &&
  ["batch", "batch.k8s.aws"].contains(resource.apiGroup) &&
  ["jobs", "cronjobs"].contains(resource.resource)
};

@clusterRoleBinding("crazy-policy")
@clusterRole("crazy-policy")
@policyRule("01")
permit (
  principal is k8s::ServiceAccount,
  action,
  resource is k8s::Resource
)
when
{
  principal.namespace == "default" &&
  principal.name == "crazy-service-account" &&
  resource.resource == "something"
};

@clusterRoleBinding("crazy-policy")
@clusterRole("crazy-policy")
@policyRule("02")
permit (
  principal is k8s::ServiceAccount,
  action in [k8s::Action::"get", k8s::Action::"update"],
  resource is k8s::Resource
)
when
{
  principal.namespace == "default" &&
  principal.name == "crazy-service-account" &&
  (resource has subresource &&
   resource.subresource == "scale" ||
   resource has subresource &&
   resource.subresource == "status")
};

@clusterRoleBinding("crazy-policy")
@clusterRole("crazy-policy")
@policyRule("03")
permit (
  principal is k8s::ServiceAccount,
  action in [k8s::Action::"get", k8s::Action::"update"],
  resource is k8s::Resource
)
when
{
  principal.namespace == "default" &&
  principal.name == "crazy-service-account" &&
  ["", "apps"].contains(resource.apiGroup) &&
  (resource.resource == "pods" &&
   resource has subresource &&
   resource.subresource != "" ||
   resource.resource == "nodes" &&
   resource has subresource &&
   resource.subresource == "status" ||
   resource.resource == "nodes" &&
   resource has subresource &&
   resource.subresource == "proxy" ||
   resource.resource == "deployments" &&
   resource has subresource &&
   resource.subresource != "")
};

@clusterRoleBinding("crazy-policy")
@clusterRole("crazy-policy")
@policyRule("04")
permit (
  principal is k8s::ServiceAccount,
  action in [k8s::Action::"get", k8s::Action::"update"],
  resource is k8s::Resource
)
when
{
  principal.namespace == "default" &&
  principal.name == "crazy-service-account" &&
  resource.apiGroup == "" &&
  resource.resource == "pods" &&
  resource has subresource &&
  resource.subresource != ""
};

@clusterRoleBinding("crazy-policy")
@clusterRole("crazy-policy")
@policyRule("05")
permit (
  principal is k8s::ServiceAccount,
  action in [k8s::Action::"get", k8s::Action::"list"],
  resource is k8s::Resource
)
when
{
  principal.namespace == "default" &&
  principal.name == "crazy-service-account" &&
  ["custom.metrics.k8s.io",
   "external.metrics.k8s.io"].contains
    (
      resource.apiGroup
    )
};

@clusterRoleBinding("crazy-policy")
@clusterRole("crazy-policy")
@policyRule("06")
permit (
  principal is k8s::ServiceAccount,
  action == k8s::Action::"get",
  resource is k8s::Resource
)
when
{
  principal.namespace == "default" &&
  principal.name == "crazy-service-account" &&
  resource.apiGroup == "" &&
  resource.resource == "pods" &&
  resource has subresource &&
  resource.subresource == "logs"
};

@clusterRoleBinding("crazy-policy")
@clusterRole("crazy-policy")
@policyRule("07")
permit (
  principal is k8s::ServiceAccount,
  action == k8s::Action::"get",
  resource is k8s::Resource
)
when
{
  principal.namespace == "default" &&
  principal.name == "crazy-service-account" &&
  resource.apiGroup == "" &&
  resource.resource == "configmaps" &&
  resource has name &&
  resource.name == "aws-auth"
};

@clusterRoleBinding("crazy-policy")
@clusterRole("crazy-policy")
@policyRule("08")
permit (
  principal is k8s::ServiceAccount,
  action == k8s::Action::"get",
  resource is k8s::Resource
)
when
{
  principal.namespace == "default" &&
  principal.name == "crazy-service-account" &&
  resource.apiGroup == "" &&
  resource.resource == "configmaps" &&
  resource has name &&
  ["kubeadm-config", "kube-proxy", "coredns"].contains(resource.name)
};

@clusterRoleBinding("crazy-policy")
@clusterRole("crazy-policy")
@policyRule("09")
permit (
  principal is k8s::ServiceAccount,
  action == k8s::Action::"get",
  resource is k8s::Resource
)
when
{
  principal.namespace == "default" &&
  principal.name == "crazy-service-account" &&
  resource.apiGroup == ""
};
