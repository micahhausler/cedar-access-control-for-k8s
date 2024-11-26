# Introduction to Cedar

This guide provides an introduction to Cedar

## Policy
If you're not familiar with Cedar, [Cedar policies] are structured with a Principal, Action, Resource, and optional Condition (PARC). Denials are implicit, but explicit `forbid`s have priority over `permit`s.

[Cedar policies]: https://docs.cedarpolicy.com/policies/syntax-policy.html

```cedar
permit (
    principal == MyPrincipalType::"some-uuid",
    action == Action::"some-action-name",
    resource == MyResourceType::"some-uuid"
);

forbid (
    principal == MyPrincipalType::"some-uuid",
    action == Action::"some-other-action-name",
    resource == MyResourceType::"some-uuid"
);
```

Every principal and resource is an [_entity_][entity], and actions are valid for specific principal and resource entity types.
Entities can also be contained by other entities.
Below is an example of a policy referencing a principal _entity_ group type.
In this example, a principal must be in the specified group, the action must be a "get" or "list", the resource must have an attribute titled `some_attribute_value` with the value `cool_value`, but the resource attribute `my_kind_attribute` must not be `secrets`.

[entity]: https://docs.cedarpolicy.com/policies/syntax-entity.html

```cedar
permit (
    principal in MyPrincipalGroupType::"my-group-identifier",
    action in [Action::"get", Action::"list"], // match multiple actions
    resource is MyResourceType
)
// optional condition clause that applies the effect when true
when {
    resource.some_attribute_name == "cool_value"
}
// optional negating condition clause, effect does not apply when true
unless {
    resource.my_kind_attribute == "secrets"
};
```

Cedar also supports namespacing entities and actions.
The previous examples used the "empty" namespace, with no prefix, but if you needed two actions or entities with the same name but acting on different types or differing structures, you can define them in separate namespaces.
Namespaces are double colon separated (`::`).
In this example, there is a `k8s` namespace with a `User` entity, a `k8s::admission` namespace with a `create` Action, and a `core::v1` namespace that has a `ConfigMap` entity.

```cedar
forbid (
    principal is k8s::User,
    action == k8s::admission::Action::"create",
    resource is core::v1::ConfigMap
) when {
    principal.name == "test-user" &&
    resource.metadata.name == "test-config"
};
```

## Request Evaluation

How does Cedar know if a principal is in a group? 
When evaluating a request, Cedar has several inputs.
(You can play with some examples for Kubernetes in the [Cedar Playground](https://www.cedarpolicy.com/en/playground)):

* A JSON list of entity structures to be considered
* A principal identifier, which must be in the entities list
* A resource identifier, which must be in the entities list
* An action
* Request context

If an entity is a member of another entity type, the Entities list must say so. Here's a very short example entities list
```json
[
    {
        "uid": { "type": "k8s::User", "id": "507B11AD-4DE0-44B1-AB7C-99C0C04854B1"},
        "attrs": {
            "uid": "507B11AD-4DE0-44B1-AB7C-99C0C04854B1",
            "name": "alice"
        },
        "parents": [
            {
                "type": "k8s::Group",
                "id": "viewers"
            }
        ]
    },
    {
        "uid": {
            "type": "k8s::Group",
            "id": "viewers"
        },
        "attrs": {},
        "parents": []
    },
    {
        "uid": {
            "type": "k8s::Resource",
            "id": "/api/v1/namespaces/default/pods/pod1/logs"
        },
        "attrs": {
            "resource": "pods",
            "namespace": "default",
            "resourceName": "pod1",
            "subresource": "logs",
            "apiGroup": ""
        },
        "parents": []
    }
]
```

Given the above input, the entity with the id `507B11AD-4DE0-44B1-AB7C-99C0C04854B1` and the name `alice` has a `parents` reference to the Group type named `viewers`, so in this case Alice is a member of the group `viewers`.
Cedar also supports membership on resource entities and verbs, which we'll get to later.

## Schema

When writing policy how do you know what is a valid attribute of a type so you can write policy against it?
Cedar policy supports a [schema] defining all valid entities (principals and resources), their attributes, actions, which actions apply to which entities (principal and resources), and what the context structure for a given action is.
You can see the Cedar schema used for Kubernetes authorization this project in [human][authz_human_schema] and [json][authz_json_schema] format.

[schema]: https://docs.cedarpolicy.com/schema/schema.html
[authz_human_schema]: ../cedarschema/k8s-authorization.cedarschema
[authz_json_schema]: ../cedarschema/k8s-authorization.cedarschema.json

Additionally, we've provided an example generated schema for all built-in Kubernetes types.
You can review these in [human][full_human_schema] and [json][full_json_schema] format.

[full_human_schema]: ../cedarschema/k8s-full.cedarschema
[full_json_schema]: ../cedarschema/k8s-full.cedarschema.json

Cedar policies can be evaluated against a schema to prove that the policy is valid. The [Cedar Go][cedar_go] library does not yet support schema validation of policy, but the rust library and CLI tool do. The example schema used in this project can be used with the [cedar CLI][cedar_cli] to validate policies.
```sh
make build
# Convert all ClusterRoleBindings and referenced ClusterRoles in your cluster to Cedar, store them to a file
./bin/converter clusterrolebindings > all-crbs.cedar
./bin/converter rolebindings > all-rbs.cedar

# Install cedar
cargo install cedar-policy-cli

# Validate the policies against the schema
cedar validate -s ./cedarschema/k8s-full.cedarschema --schema-format cedar -p all-crbs.cedar
cedar validate -s ./cedarschema/k8s-full.cedarschema --schema-format cedar -p all-rbs.cedar
```

[cedar_go]: https://pkg.go.dev/github.com/cedar-policy/cedar-go
[cedar_cli]: https://crates.io/crates/cedar-policy-cli

The Makefile includes a target to validate all `.cedar` poilcy files in this repostiory.

```bash
make validate
```

To regenerate all schema files in both JSON and cedar formats (`k8s-full.cedarschema` and `k8s-full.cedarschema.json`), run:

```sh
make cedarschemas
```
