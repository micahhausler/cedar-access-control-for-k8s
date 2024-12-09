# Limitations

## Implicit subresources

Kubernetes RBAC doesn't permit requests on subresources unless a resources's subresource is explicitly named, or uses a wildcard (`*`).

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: get-services
rules:
- apiGroups:
  - ""
  resources:
  - services
  verbs:
  - "get"
  - "list"
```

The above policy does not allow port forwarding (ex: `kubectl port-forward -n kube-system svc/kube-dns`), because no `port-forward` subresource was specified, even though the apiGroup, verb, and resource matched the reqeust.

RBAC would require the following policy to permit a port-forward request.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: service-port-forwarder
rules:
- apiGroups:
  - ""
  resources:
  - services/portforward
  verbs:
  - "get"
```

Because subresources are modeled as an entity attribute in Cedar, the following policy does permit port-forward requests to services, because the verb, apiGroup and resource type match.

```cedar
permit (
    principal in k8s::Group::"read-only-group",
    action in [k8s::Action::"get", k8s::Action::"list"],
    resource is k8s::Resource
) when {
    resource.apiGroup == "" && resource.resource == "services"
};
```

In order to allow service listing while preventing subresources like port-forward, a condition excluding subresources is required:
```cedar
permit (
    principal in k8s::Group::"read-only-group",
    action in [k8s::Action::"get", k8s::Action::"list"],
    resource is k8s::Resource
) when {
    resource.apiGroup == "" && resource.resource == "services"
} unless {
    resource has subresource
};
```

## RBAC Conversion limitations

See [RBAC conversion documentation](./ConvertRBAC.md#limitations)

## Expressiveness limitations

A core tenet of Cedar is to be analyzable, meaning that the language can verify that a policy is valid and will not error.
A general `map`/`filter` function on dynamic inputs and ordered lists [are not analyzible][rfc21], and not a candidate for Cedar.
This prevents specifically checking subfields over sets of structures, which is a common Kubernetes policy management requirement.
Cedar is powered by [automated reasoning], including an [SMT solver], which does not implement loops or map functions.
Rather than viewing Cedar as a replacement for admission restrictions tools like [Open Policy Agent/Gatekeeper][gatekeeper] or [Kyverno][kyverno], it is best seen as an additional tool for access control enforcement.

[rfc21]: https://github.com/cedar-policy/rfcs/pull/21#issuecomment-2109240941
[automated reasoning]: https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing
[SMT solver]: https://en.wikipedia.org/wiki/Satisfiability_modulo_theories
[gatekeeper]: https://open-policy-agent.github.io/gatekeeper/website/
[kyverno]: https://kyverno.io/

## Policy store updates and race conditions

Suppose you had a Cedar policy that permitted a principal to take one action in authorization, but had restrictions enforced as forbid policies in admission.
You decide for whatever reason you need to revoke that whole policy, so you remove that policy from your cluster.
If the identity you had granted authorization for was making a request at the same moment you removed the policy, it would be possible that the request could be permitted by the authorization webhook before the revocation was processed, and the denial removal in admission could be propagated before the Kubernetes API invokes the admission webhook, which would open the possibility of letting through a request that should have been forbidden in admission.

For now this is a limitation of Kubernetes that requires upstream work to resolve.

## Policy store tiers

For now, the policy store is a flat list of all policies as defined by CRDs in a cluster.
Any forbid policy will take precedence over an allow.
Right now, its possible for a user to write a policy that forbids all requests in a cluster:
```cedar
forbid (
    principal,
    action,
    resource
);
```
To guard against this, we'll likely add support for multiple tiers of policy stores, potentially from policy stores outside the cluster.
In each tier, if no explicit `permit` or `forbid` applies to a request, the authorizer would progress to the next tier.

## No permission enumeration

Kubernetes enables users to list their permissions, and that functionality is [closely tied to RBAC's policy rule implementation][ruleResolver].
Kubernetes can interrogate built-in authorizers for all permission rules that apply to a user:

```bash
kubectl auth can-i --list
# Warning: the list may be incomplete: webhook authorizer does not support user rule resolution
```

There is currently no plan upstream to expand this to webhook authorizers, which doesn't impact this project, as Cedar cannot enumerate all permissions.

[ruleResolver]: https://pkg.go.dev/k8s.io/apiserver@v0.31.1/pkg/authorization/authorizer#RuleResolver

## No privilege escalation prevention

Kubernetes has [built-in protections for privilege escalation in RBAC][privesc-rbac] for creating new policies (`escalate` verb) and on creating or updating bindings (`bind` verb).
It can perform these checks because RBAC includes permission enumeration.
Full policy enumeration is impossible with Cedar, as it supports features like string wildcards.
Cedar could potentially add some basic level of support for privilege escalation, but the topic requires further exploration.

[privesc-rbac]: https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping
