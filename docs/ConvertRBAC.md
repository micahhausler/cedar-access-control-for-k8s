# Convert RBAC policies

There's an RBAC converter that works on ClusterRoleBindings or RoleBindings.
This converter is intended to help you transition any RBAC policies you want to add conditions to into Cedar.
Any existing RBAC policies that aren't denied by a Cedar policy will still work.

If not done already, clone this repository to your local environment or IDE.

```bash
git clone https://github.com/awslabs/cedar-access-control-for-k8s.git
cd cedar-access-control-for-k8s
```

You can convert all CRBs/RBs by specifing a type with no names, or a comma-separated list of names after the type.
You can add `--output=crd` to emit Policy CRD YAML containing the cedar policies.

```bash
./bin/converter clusterrolebinding --format cedar > all-crb.cedar
./bin/converter clusterrolebinding --format crd > all-crb.yaml

./bin/converter rolebinding --format cedar > all-rb.cedar
./bin/converter rolebinding --format crd > all-rb.yaml
```

Which yields

```cedar
// cluster-admin
@clusterRoleBinding("cluster-admin")
@clusterRole("cluster-admin")
@policyRule("01")
permit (
  principal in k8s::Group::"system:masters",
  action,
  resource is k8s::NonResourceURL
);

@clusterRoleBinding("cluster-admin")
@clusterRole("cluster-admin")
@policyRule("00")
permit (
  principal in k8s::Group::"system:masters",
  action,
  resource is k8s::Resource
);
// ...
```

## Limitations

### Mixed apiGroups, resources, and verbs

Kubernetes RBAC allows you to specify multiple API groups and resources in a rule, some of which are invalid Cedar and will never be authorized, as certain resources only existin specific API groups, or verbs only apply to specific resource types.
For example, `pods` resources only exist in the core API group (`apiGroups: [""]`).
Similarly, the `users` and `groups` resources only are in the `authentication.k8s.io` API group, and the `impersonation` verb only applies to the resources in that API group.

The following is valid RBAC policy, but will never return an allowed response, as the `get` verb doesn't apply to the apiGroup and resource.
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: impersonator
rules:
- apiGroups:
  - authentication.k8s.io
  resourceNames:
  - hoth
  resources:
  - userextras/planets
  verbs:
  - get # <-- verb doesn't apply to this apiGroup or the resources in it
```

### Impersonation

Nearly all features of authorizing Kubernetes impersonation work in Cedar, with the exception of impersonating extra values without a key.
The following RBAC policy is valid, and allows any user bound to this policy to impersonate any extra key, so long as the value is `"hoth"`.
Because Cedar uses entity tags (key/values) and does not have a `.hasValue()` operator, this poilcy cannot be converted to Cedar.
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: impersonator
rules:
- apiGroups:
  - authentication.k8s.io
  resourceNames:
  - hoth  # <-- only this value is allowed
  resources:
  - userextras # <-- any key is allowed
  verbs:
  - impersonate
```

### Implicit attributes and read-only actions

Kubernetes does not authorize requests including subresources, unless there is an explicit allow on a subresource, which differs from how Kubernetes handles other authorization fields like `resourceName`.
Cedar implicitly authorizes requests including a field unless there is an explicit condition forbidding or permitting the field.
For example, the following Kubernetes RBAC policy does permit listing or getting any pod in any namespace, but does not permit `get` verbs on any subresource.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: impersonator
rules:
- apiGroups:
  - ""
  resources:
  - pods
  verbs:
  - get
```

A naive translation to Cedar would look like
```cedar
// NOT CORRECT
permit (
  principal,
  action == k8s::Action::"get",
  resource is k8s::Resource
) when {
  resource.apiGroup == "" &&
  resource.resource == "pods"
};
```

However this is subtly incorrect for multiple reasons.
First, the `pods` resource has numerous subresources, including a `get` on `/logs`, which allows a reader to access the pod's logs.

```cedar
// NOT CORRECT
permit (
  principal,
  action == k8s::Action::"get",
  resource is k8s::Resource
) when {
  resource.apiGroup == "" &&
  resource.resource == "pods"
} unless {
  resource has subresource // rule does not apply if subresource is present
};
```

### Explicit namespaces and cluster-scoped requests

Similar to the above example, say you want to prevent a prinicipal who manages Kubernetes secrets from accessing secrets in the kube-system namespace.
You might author a policy similar to the one below, with a permit on secrets and a forbid on secrets in kube-system.

```cedar
// NOT CORRECT
permit (
  principal in k8s::Group::"secret-manager",
  action == k8s::Action::"list",
  resource is k8s::Resource
) when  {
  resource.resource == "secrets"
};

forbid (
  principal in k8s::Group::"secret-manager",
  action == k8s::Action::"list",
  resource is k8s::Resource
) when  {
  resource.resource == "secrets"
  resource.namespace == "kube-system"
};
```

While the above policy will successfully only allow namespace-scoped list requests to namespaces other than kube-system, it fails to restrict cluster-scoped requests.

```bash
kubectl get secrets --namespace=kube-system # will be forbidden
kubectl get secrets --all-namespaces # will be permitted
```

To correctly restrict cluster scoped requests, we must add an additional condition to the `permit` policy.

```cedar
permit (
  principal in k8s::Group::"secret-manager",
  action == k8s::Action::"list",
  resource is k8s::Resource
) when  {
  resource.resource == "secrets" &&
  resource has namespace  // <-- requires namespace to be set
};

// NOT CORRECT
forbid (
  principal in k8s::Group::"secret-manager",
  action == k8s::Action::"list",
  resource is k8s::Resource
) when  {
  resource.resource == "secrets"
  resource.namespace == "kube-system"
};
```