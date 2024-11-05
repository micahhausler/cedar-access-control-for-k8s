# Cedar Schemas

Cedar supports defining a [schema] with which policies can be validated from.
Schemas also serve as a way to document what attributes each entity.

This project uses the [cedar-policy/cedar-go][cedar-go] library, which does [not yet support schema validation][cedar-go-schema] of policies.
The referenced schemas are primarily created to document the entity shapes and actions that the project uses today, and help policy authors validate their policies.

[schema]: https://docs.cedarpolicy.com/schema/schema.html
[cedar-go]: https://github.com/cedar-policy/cedar-go
[cedar-go-schema]: https://github.com/cedar-policy/cedar-go/issues/2

## Authorizer cedarschema

For the full authorization schema, see [cedarschema/k8s-authorization.cedarschema](../cedarschema/k8s-authorization.cedarschema).

### Principals

This project supports the following Principal entities:

* `k8s::Group`. Groups are identified by the group name in policy.
    ```cedarschema
    entity Group;
    ```
* `k8s::User`. Users are identified by the user's UID as reported by the authenticator.
    The group list comes in from the Kubernetes authenticator (webhook, serviceaccount, OIDC, etc), so we dynamically build the list of group Entities for a request.
    Kubernetes authenticators can also includes extra key/value information on a user, and that is encoded in the 'extra' attribute.
    ```cedarschema
    entity User in [Group] = {
        "extra"?: Set < ExtraAttribute >,
        "name": __cedar::String
    };
	type Extra = {
		"key": __cedar::String,
		"values"?: Set < __cedar::String >
	};
    ```
* `k8s::ServiceAccount`. When a user's name in a [SubjectAccessReview] starts with `system:serviceaccount:`, the authorizer sets the principal type to `k8s::ServiceAccount` with the following attributes.
    ```cedarschema
    entity ServiceAccount in [Group] = {
        "extra"?: Set < ExtraAttribute >,
        "name": __cedar::String,
        "namespace": __cedar::String
    };
    ```
* `k8s::Node`. When a user's name in a [SubjectAccessReview] starts with `system:node:`, the authorizer sets the principal type to `k8s::Node` with the following attributes.
    Most node authorization happens in the in-tree NodeAuthorizer and happens before a Cedar decision, but there are some rules the NodeAuthorizer delegates to RBAC and the NodeRestriciton Admission plugin.
    Cedar can allow or forbid any of those reqeusts.
    ```cedarschema
    entity Node in [Group] = {
        "extra"?: Set < ExtraAttribute >,
        "name": __cedar::String
    };
    ```

[SubjectAccessReview]: https://pkg.go.dev/k8s.io/api@v0.31.1/authorization/v1#SubjectAccessReviewSpec

### Actions

Authorization actions are pretty simple, just the `verb` name from the Kubernetes request. The following policy would allow any user in the group `viewers` to `get`/`list`/`watch` on any request, unless the request's resource has the field `resource` and the value of `resource` is `secrets`.

```cedar
permit (
    principal in k8s::Group::"viewers",
    action in [k8s::Action::"get", k8s::Action::"list", k8s::Action::"watch"],
    resource is k8s::Resource
) unless {
    resource.resource == "secrets" &&
    resource.apiGroup == "" // "" is the core API group in Kubernetes
};
```

We do have a resource group for all readOnly actions. It encompasses `get`/`list`/`watch`, and is called `readOnly`, and only applies to `k8s::Resource` resources.

```cedar
permit (
    principal in k8s::Group::"viewers",
    action in k8s::Action::"readOnly", // allows any get/list/watch
    resource is k8s::Resource
) unless {
    resource.resource == "secrets" &&
    resource.apiGroup == "" // "" is the core API group in Kubernetes
};
```

### Resources

> Note: `"resource"`, `"k8s::Resource"`, and `"resource.resource`, why the redundancy?!
>
> This is an unfortunate naming collision. Cedar policies always have a `resource` as part of the policy.
> We call Kubernetes typed objects `k8s::Resource` as opposed to the `k8s::NonResourceURL` type, because that's what Kubernetes calls them.
> And finally, Kubernetes authorization checks refer to they type of object as a `resource`, along with the object's `apiGroup`, `namespace`, `name`, etc.

We define two primary resource types for this authorizer:

* `NonResourceURL`: This is for non-resource requests made to the Kubernetes API server. Examples include `/healthz`, `/livez`, `/metrics`, and subpaths. (Hint: run `kubectl get --raw /` to see others) Paths can match a `*` on the suffix.
    ```cedarschema
    entity NonResourceURL = {
        "path": __cedar::String
    };
    ```
    Examples:
    ```cedar
    // allow multiple URLs
    permit (
        principal in k8s::Group::"system:authenticated",
        action == k8s::Action::"get",
        resource is k8s::NonResourceURL
    ) when {
        ["/version", "/healthz"].contains(resource.path) ||
        resource.path like "/healthz/*"
    };
    // explicitly list one path
    permit (
        principal in k8s::Group::"version-getter",
        action == k8s::Action::"get",
        resource == k8s::NonResourceURL::"/version"
    );
    ```
* `Resource`: This is for resource requests made to the Kubernetes API server. Entity IDs on resources are the constructed URL path being made for the request.
    ```cedarschema
    entity Resource = {
        "apiGroup": __cedar::String,
        "fieldSelector"?: Set < FieldRequirement >,
        "labelSelector"?: Set < LabelRequirement >,
        "name"?: __cedar::String,
        "namespace"?: __cedar::String,
        "resource": __cedar::String,
        "subresource"?: __cedar::String
    };
    ```
    Examples:
    ```cedar
    // "viewers" group members can get/list/watch any Namespaced other than secrets
    permit (
        principal in k8s::Group::"viewers",
        action in [ k8s::Action::"get", k8s::Action::"list", k8s::Action::"watch"],
        resource is k8s::Resource
    ) unless {
        resource.resource == "secrets" &&
        // "" is the core API group in Kubernetes
        resource.apiGroup == ""
        // any/all namespaces
    };

    // Allow developers to manage deployments in any namespace other than kube-system or kube-public
    permit (
        principal in k8s::Group::"developers",
        action in [
            k8s::Action::"get",
            k8s::Action::"list",
            k8s::Action::"watch",
            k8s::Action::"create",
            k8s::Action::"update",
            k8s::Action::"delete"],
        resource is k8s::Resource
    ) when {
        resource.resource == "deployments" &&
        resource.apiGroup == "apps" &&
        // require a namespace name so cluster-scoped collection requests are not permitted
        resource has namespace 
    } unless {
        // permit does not apply under these conditions
        resource has namespace &&
        ["kube-system", "kube-public" ].contains(resource.namespace)
    };
    ```

`Resource` has a `fieldSelector` and `labelSelector` types. These were added in Kubernetes 1.31 behind the [`AuthorizeWithSelectors`][AuthorizeWithSelectors] feature gate so authorizers can enforce that a watch or list request has a field or label selector:

[AuthorizeWithSelectors]: https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/

```cedarschema
type FieldRequirement = {
    "field": __cedar::String,
    "operator": __cedar::String,
    "value": __cedar::String
};

type LabelRequirement = {
    "key": __cedar::String,
    "operator": __cedar::String,
    "values": Set < __cedar::String >
};
```

This can be used to enforce attribute-based access policies, such as a user can only get/list/watch resources where the label `owner` equals the user's name
```cedar
permit (
    principal is User,
    action in [k8s::Action::"list", k8s::Action::"watch"],
    resource is k8s::Resource
) when {
    // "" is the core API group in Kubernetes
    resource.apiGroup == "" &&
    resource.resource == "configmaps" &&
    resource has labelSelector &&
    resource.labelSelector.containsAny([
        {"key": "owner","operator": "=", "values": [principal.name]},
        {"key": "owner","operator": "==", "values": [principal.name]},
        {"key": "owner","operator": "in", "values": [principal.name]}])
};
```

For the user `test-user`, the first request would fail, but the second will succeed:
```sh
$ KUBECONFIG=./mount/test-user-kubeconfig.yaml kubectl get secrets
Error from server (Forbidden): secrets is forbidden: User "test-user" cannot list resource "secrets" in API group "" in the namespace "default"

$ KUBECONFIG=./mount/test-user-kubeconfig.yaml kubectl get secrets -l owner=test-user
NAME             TYPE     DATA   AGE
example-secret   Opaque   1      2d20h

# as admin
$ kubectl get secrets --show-labels
NAME                   TYPE     DATA   AGE     LABELS
example-secret         Opaque   1      2d20h   owner=test-user
other-example-secret   Opaque   1      2d20h   owner=prod-user
```

#### Impersonated resources

To make an impersonated request as another user, Kubernetes sends multiple authorization requests to an authorizer: one for each attribute being impersonated: The user's name, the UID (if set), the groups (if set), and the userInfo extra key/value map (entity tags are [not yet supported in cedar-go](https://github.com/cedar-policy/cedar-go/issues/47)). To support this, we define a few types:

* `Group`. This structure is the same from the principal type. This only functions if the user can also impersonate the requested username.:
    ```cedar
    permit (
        principal in k8s::Group::"actors",
        action == k8s::Action::"impersonate",
        resource == k8s::Group::"superheros"
    );
    ```
* `User`. This structure is the same from the principal type:
    ```cedar
    permit (
        principal is k8s::User,
        action == k8s::Action::"impersonate",
        resource is k8s::User
    ) when {
        principal.name == "markhamill" &&
        resource.name == "lukeskywaker"
    };
    ```
* `PrincipalUID`: To allow impersonating a Principal's UID, the policy's resource type must be `PrincipalUID`. This only functions if the user can also impersonate the requested username.
    ```cedarschema
    entity PrincipalUID;
    ```
    Examples:
    ```cedar
    permit (
        principal in k8s::Group::"actors",
        action == k8s::Action::"impersonate",
        resource == k8s::PrincipalUID::"26A82C8D-CC8B-49BB-B2CF-070B9CF1A4F8"
    );
    ```
* `Extra`: To allow impersonating a principal's key/values extra info, the policy's resource type must be `Extra`. This only functions if the user can also impersonate the requested username.
    ```cedarschema
    entity PrincipalUID;
    ```
    Examples:
    ```cedar
    permit (
        principal in k8s::Group::"actors",
        action == k8s::Action::"impersonate",
        resource is k8s::Extra
    ) when {
        resource.key == "order" &&
        resource has values &&
        ["jedi"].containsAll(resource.values)
    };
    ```
* `ServiceAccount` This structure is the same from the principal type:
   ```cedar
    permit (
        principal is k8s::ServiceAccount,
        action == k8s::Action::"impersonate",
        resource is k8s::ServiceAccount
    ) when {
        principal.name == "kube-controller-manager" &&
        principal.namespace == "kube-system" &&
        resource.name == "service-account-controller" &&
        resource.namespace == "kube-system"
    };
    ```
* `Node` This structure is the same from the principal type:
   ```cedar
    // On Kubernetes versions 1.29+ with the `ServiceAccountTokenPodNodeInfo` flag enabled,
    // Kubernetes injects a node name into the Service Account token, which gets propagated
    // into the user's info extra map. We transform the map into a set of key/value
    // records with key of string and value as a set of strings.
    //
    // This allows a service account to impersonate only the node included in the SA token's
    // node claim, which practicly translates to "only impersonate the node a pod is running on"
    permit (
        principal is k8s::ServiceAccount,
        action == k8s::Action::"impersonate",
        resource is k8s::Node
    ) when {
        principal.name == "default" &&
        principal.namespace == "default" &&
        principal has extra &&
        principal.extra.contains({
            "key": "authentication.kubernetes.io/node-name",
            "values": [resource.name]})
    };
    ```

## Admission Webhook overview

To see a generated schema with all admission entities and actions, you can view [k8s-full.cedarschema](../cedarschema/k8s-full.cedarschema).

This package also contains a webhook that can evaluate Kubernetes requests in the Admission validation stage, evaluating the full request object.
Unlike authorization which is deny by default, Cedar Admission policies are allow by default, so only `forbid` policies have any effect on admission.
The admission webhook automatically injects a the following Cedar policy for every request, which applies to all admission requests.
```cedar
permit (
    principal,
    action in [
        k8s::admission::Action::"create",
        k8s::admission::Action::"update",
        k8s::admission::Action::"delete",
        k8s::admission::Action::"connect"],
    resource
);
```

### Principals

Principals in the admission webhook are identical to the entities used in Authorization, including ServiceAccounts and Group membership.

### Actions

Validating Admission requests are only made for mutating requests, so only create, update, delete, and connect are admissible.
Admission actions exist in a different Cedar namespace than Authorization, and are prefixed with `k8s::admission::Action`.
```cedar
// largely redundant policy, as authorization already only allows non-mutating verbs on resources
forbid (
    principal in k8s::Group::"system:viewers",
    action in [
        k8s::admission::Action::"create", 
        k8s::admission::Action::"update", 
        k8s::admission::Action::"delete"],
    resource
);
```

All admission actions currently apply to any Kubernetes type that have a [`metav1.ObjectMeta`][objmeta] or [`corev1.ListMeta`][listmeta].

[objmeta]: https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1#ObjectMeta
[listmeta]: https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1#ListMeta

### Resources

Resources for Admission policies are derived from the Kubernetes API Group and version.
The resource entity structure matches that of the Kubernetes API structure, with some special cases.

```cedar
// Forbid pods with hostNetwork in namespaces other than kube-system
forbid (
    principal,
    action in [k8s::admission::Action::"create", k8s::admission::Action::"update"],
    resource is core::v1::Pod
) when {
    resource has spec &&
    resource.spec has hostNetwork &&
    resource.spec.hostNetwork == true
} unless {
    resource has metadata &&
    resource.metadata has namespace &&
    resource.metadata.namespace == "kube-system"
};
```

Until [cedar-go supports entity maps][go-entity-maps], we've manually added `KeyValue` and `KeyValues` types into the `meta::v1` namespace to support key/value labels.
Any Kubernetes types that consist of `map[string]string{}` or `map[string][]string{}` are converted to a Set of KeyValue or KeyValueStringSlice.
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
    // ...
    entity ObjectMeta = {
        "annotations"?: Set < meta::v1::KeyValue >,
        "labels"?: Set < meta::v1::KeyValue >,
        // ...
        "name"?: __cedar::String,
        "namespace"?: __cedar::String,
        // ...
    };
    // ...
}
```

[go-entity-maps]: https://github.com/cedar-policy/cedar-go/issues/47
