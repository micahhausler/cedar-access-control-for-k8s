@clusterRoleBinding("impersonator")
@clusterRole("impersonator")
@policyRule("00")
permit (
  principal is k8s::User,
  action == k8s::Action::"impersonate",
  resource
)
when
{
  principal.name == "impersonator" &&
  (resource is k8s::User &&
   resource.name == "jedi" ||
   resource is k8s::Group &&
   resource.name == "jedi")
};

@clusterRoleBinding("impersonator")
@clusterRole("impersonator")
@policyRule("01")
permit (
  principal is k8s::User,
  action == k8s::Action::"impersonate",
  resource
)
when
{
  principal.name == "impersonator" &&
  (resource == k8s::PrincipalUID::"jedi" ||
   resource is k8s::Extra &&
   resource.hasTag("mykey") &&
   resource.getTag("mykey") == "jedi")
};

@clusterRoleBinding("impersonator")
@clusterRole("impersonator")
@policyRule("02")
permit (
  principal is k8s::User,
  action == k8s::Action::"impersonate",
  resource
)
when
{
  principal.name == "impersonator" &&
  (resource is k8s::PrincipalUID &&
   resource in [k8s::PrincipalUID::"jedi", k8s::PrincipalUID::"sith"] ||
   resource is k8s::Extra &&
   resource.hasTag("mykey") &&
   (resource.getTag("mykey") == "jedi" || resource.getTag("mykey") == "sith"))
};
