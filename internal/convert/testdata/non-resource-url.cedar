@clusterRoleBinding("non-resource-url-group")
@clusterRole("non-resource-url-group")
@policyRule("00")
permit (
  principal in k8s::Group::"non-resource-url-actor",
  action in [k8s::Action::"get", k8s::Action::"options"],
  resource is k8s::NonResourceURL
);

@clusterRoleBinding("non-resource-url-group")
@clusterRole("non-resource-url-group")
@policyRule("01")
permit (
  principal in k8s::Group::"non-resource-url-actor",
  action == k8s::Action::"get",
  resource is k8s::NonResourceURL
)
when { resource.path like "/healthz/\*" };

@clusterRoleBinding("non-resource-url-group")
@clusterRole("non-resource-url-group")
@policyRule("02")
permit (
  principal in k8s::Group::"non-resource-url-actor",
  action == k8s::Action::"get",
  resource is k8s::NonResourceURL
)
when
{
  resource.path like "/readyz/\*" ||
  resource.path like "/version/\*" ||
  ["/version", "/version/"].contains(resource.path)
};

@clusterRoleBinding("non-resource-url-group")
@clusterRole("non-resource-url-group")
@policyRule("03")
permit (
  principal in k8s::Group::"non-resource-url-actor",
  action == k8s::Action::"get",
  resource is k8s::NonResourceURL
)
when { resource.path == "/metrics" };

@clusterRoleBinding("non-resource-url-group")
@clusterRole("non-resource-url-group")
@policyRule("04")
permit (
  principal in k8s::Group::"non-resource-url-actor",
  action == k8s::Action::"get",
  resource is k8s::NonResourceURL
)
when
{ resource.path like "/openapi/v3/\*" || resource.path like "/openid/v1/\*" };

@clusterRoleBinding("non-resource-url-group")
@clusterRole("non-resource-url-group")
@policyRule("05")
permit (
  principal in k8s::Group::"non-resource-url-actor",
  action == k8s::Action::"get",
  resource is k8s::NonResourceURL
)
when { resource.path like "/openapi/v3/\*" || resource.path == "/openapi/v3" };

@clusterRoleBinding("non-resource-url-group")
@clusterRole("non-resource-url-group")
@policyRule("06")
permit (
  principal in k8s::Group::"non-resource-url-actor",
  action == k8s::Action::"get",
  resource is k8s::NonResourceURL
)
when { ["/openapi/v3", "/openapi/v2"].contains(resource.path) };
