@clusterRoleBinding("impersonator")
@clusterRole("impersonator")
@policyRule("00")
permit (
  principal is k8s::User,
  action == k8s::Action::"impersonate",
  resource is k8s::Extra
)
when
{
  principal.name == "impersonator" &&
  resource.key == "planets" &&
  resource has value &&
  ["hoth", "tatooine"].contains(resource.value)
};

@clusterRoleBinding("impersonator")
@clusterRole("impersonator")
@policyRule("01")
permit (
  principal is k8s::User,
  action == k8s::Action::"impersonate",
  resource is k8s::Extra
)
when
{
  principal.name == "impersonator" &&
  resource.key == "father" &&
  resource has value &&
  resource.value == "anakin"
};

@clusterRoleBinding("impersonator")
@clusterRole("impersonator")
@policyRule("02")
permit (
  principal is k8s::User,
  action == k8s::Action::"impersonate",
  resource is k8s::Extra
)
when
{
  principal.name == "impersonator" &&
  resource has value &&
  ["hoth", "tatooine"].contains(resource.value)
};

@clusterRoleBinding("impersonator")
@clusterRole("impersonator")
@policyRule("03")
permit (
  principal is k8s::User,
  action == k8s::Action::"impersonate",
  resource is k8s::User
)
when { principal.name == "impersonator" && resource.name == "lukeskywalker" };

@clusterRoleBinding("impersonator")
@clusterRole("impersonator")
@policyRule("04")
permit (
  principal is k8s::User,
  action == k8s::Action::"impersonate",
  resource is k8s::Group
)
when
{
  principal.name == "impersonator" &&
  ["jedi", "padawan"].contains(resource.name)
};

@clusterRoleBinding("impersonator")
@clusterRole("impersonator")
@policyRule("05")
permit (
  principal is k8s::User,
  action == k8s::Action::"impersonate",
  resource == k8s::PrincipalUID::"DB8EEC53-C32A-4D62-8BB2-A4B6126E9193"
)
when { principal.name == "impersonator" };

@clusterRoleBinding("impersonator")
@clusterRole("impersonator")
@policyRule("06")
permit (
  principal is k8s::User,
  action == k8s::Action::"impersonate",
  resource is k8s::PrincipalUID
)
when
{
  principal.name == "impersonator" &&
  resource in [k8s::PrincipalUID::"DB8EEC53-C32A-4D62-8BB2-A4B6126E9193",
   k8s::PrincipalUID::"C41A46B6-4E27-43C4-9664-0A1CB8651DAC"]
};

@clusterRoleBinding("impersonator")
@clusterRole("impersonator")
@policyRule("07")
permit (
  principal is k8s::User,
  action == k8s::Action::"impersonate",
  resource is k8s::Extra
)
when
{
  principal.name == "impersonator" &&
  ["planets", "systems"].contains(resource.key) &&
  resource has value &&
  ["hoth", "tatooine"].contains(resource.value)
};

@clusterRoleBinding("impersonator")
@clusterRole("impersonator")
@policyRule("08")
permit (
  principal is k8s::User,
  action == k8s::Action::"impersonate",
  resource
)
when { principal.name == "impersonator" };

@clusterRoleBinding("impersonator")
@clusterRole("impersonator")
@policyRule("09")
permit (
  principal is k8s::User,
  action == k8s::Action::"impersonate",
  resource
)
when
{
  principal.name == "impersonator" &&
  (resource is k8s::Extra || resource is k8s::User)
};
