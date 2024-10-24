# Limitations

- [Limitations](#limitations)
  - [Entity Tags (key/value maps)](#entity-tags-keyvalue-maps)
  - [Expressiveness limitations](#expressiveness-limitations)
  - [Policy store updates and race conditions](#policy-store-updates-and-race-conditions)
  - [Policy store tiers](#policy-store-tiers)
  - [No permission enumeration](#no-permission-enumeration)
  - [No privilege escalation prevention](#no-privilege-escalation-prevention)


## Entity Tags (key/value maps)

Cedar's Rust implementation and CLI gained support for entity tags (key/value maps) in [Cedar v4.2.0][4.2].
Until [cedar-go supports entity tags][go-entity-tags], we've manually added `KeyValue` and `KeyValues` types into the `meta::v1` namespace to support key/value labels.
Any Kubernetes types in admission that consist of `map[string]string{}` or `map[string][]string{}` are converted to a Set of KeyValue or KeyValueStringSlice.
```cedarschema
namespace meta::v1 {
    type KeyValue = {
        "key": __cedar::String,
        "value"?: __cedar::String
    };
    type KeyValueStringSlice = {
        "key": __cedar::String,
        "value"?: Set < __cedar::String >
    };
    entity ObjectMeta = {
        "annotations"?: Set < meta::v1::KeyValue >,
        "labels"?: Set < meta::v1::KeyValue >,
        "name"?: __cedar::String,
        "namespace"?: __cedar::String,
        // ...
    };
    // ...
}
```

Similarly, the Authorization namespace `k8s::` includes a custom `Extra` type to support key/value maps on Users, ServiceAccounts, and Nodes.
```cedarschema
namespace k8s {
	type Extra = {
		"key": __cedar::String,
		"values"?: Set < __cedar::String >
	};
    entity User in [Group] = {
		"extras"?: Set < Extra >,
		"name": __cedar::String
	};
    // ...
}
```

[4.2]: https://github.com/cedar-policy/cedar/releases/tag/v4.2.0
[go-entity-tags]: https://github.com/cedar-policy/cedar-go/issues/47

## Expressiveness limitations

A core tenet of Cedar is to be analyzable, meaning that the language can verify that a policy is valid and will not error.
A general `map`/`filter` function on dynamic inputs [is not analyzible][rfc21], and not a candidate for the project.
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
