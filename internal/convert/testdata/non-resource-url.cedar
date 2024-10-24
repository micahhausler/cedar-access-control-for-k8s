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
when { resource has path && resource.path like "/healthz/\*" };

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
  resource has path &&
  (resource.path like "/readyz/\*" || resource.path like "/version/\*") ||
  ["/version", "/version/"].contains(resource.path)
};
