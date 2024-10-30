# Rejected features

## CEL in annotations

Rather than presenting a native structure to Cedar, its possible to pre-compute results and present them to Cedar in a format that is analyzable.
In an early prototype, the admission webhook supported embedding [CEL functions][cel] that evaluate to a boolean in Cedar annotations prefixed with `cel_context_`.
The following example included 3 CEL expressions that evaluate to true if all containers/initContainers/ephemeralContainers in the pod were from the approved registry.
The `forbid` applied to all pods in the `default` namespace, but the denial effect does not apply if all three evaluations were true.

[cel]: https://kubernetes.io/docs/reference/using-api/cel/

```cedar
@cel_context_allContainersInRegistry("self.spec.containers.all(c, c.image.startsWith(\"myregistry.com\"))")
@cel_context_allInitContainersInRegistry("self.spec.initContainers.all(c, c.image.startsWith(\"myregistry.com\"))")
@cel_context_allEphemeralContainersInRegistry("self.spec.ephemeralContainers.all(c, c.image.startsWith(\"myregistry.com\"))")
forbid (
    principal,
    action in [k8s::admission::Action::"create", k8s::admission::Action::"update"],
    resource is core::v1::Pod
) when {
    resource has metadata &&
    resource.metadata has namespace &&
    resource.metadata.namespace == "default"
} unless {
    context has allContainersInRegistry &&
    context.allContainersInRegistry &&
    context has allInitContainersInRegistry &&
    context.allInitContainersInRegistry &&
    context has allEphemeralContainersInRegistry &&
    context.allEphemeralContainersInRegistry
};
```

This functionality was removed for several reasons:
* Performance: It required parsing every individual policy to look for matching annotations, and evaluating every admission policy individually.
    This was signifivantly slower than just using the Cedar library.
* Analizability: While the above Cedar policy is still analyzable, the embedded CEL expression is not, and could error. 
* Tenet violation: One of the goals of this project is to use a unified language for admission and authorization.
    This required users to be versed in CEL and presented complexity in policy authorship.
