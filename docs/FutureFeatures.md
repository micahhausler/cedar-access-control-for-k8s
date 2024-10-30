# Potential Future Feature Ideas

The following list of feature ideas are not yet built, but potential candidates for addition.

## Multiple tiered policy stores

For this prototype, policies are all defined in as Policy custom resources.
Because all policies are evaluated together and forbids take precedence over permits, its possible to deny all requests by adding

```cedar
forbid (
    principal,
    action,
    resource
);
```

To defend against such a policy, we can introduce multiple tiers of policies with each tier evaluated independently.
If a tier has an explicit `permit` or `forbid`, we'll take that decision and skip successive tiers.
If there are no matching policies in a tier, we'll move on to the next tier.
After all Cedar tiers, Kubernetes moves on to RBAC, and then denial by default.

You can conceive of a system with the following tiers

1. Highly trusted policies in a central policy store
2. Converted policies for built-in RBAC rules, allowing controllers and other resources to function correctly
3. User-defined policies in CRDs in a cluster

## Amazon Verified Permissions integration

[Amazon Verified Permissions][avp] is an AWS service that offers a fully managed authorization service and policy store based on Cedar.
While we don't use AVP for authorizing individual Kubernetes requests currently, it could function very well as a central policy store for multiple clusters.

[avp]: https://aws.amazon.com/verified-permissions/

## Cluster metadata

Once a central policy store is used, policies could be applied to multiple clusters, and we could inject context data into evaluated requests containing cluster metadata, so users can conditionally apply policies

Imagine if every evaluated request context contained EKS cluster metadata structured like so: (EKS just being an example stand-in, it could be any provider or structure)
```json
{
    "cluster": {
        "arn": "arn:aws:eks:us-west-2:111122223333:cluster/prod-cluster-05",
        "region": "us-west-2",
        "accountId": "111122223333",
        "tags": {
            "stage": "prod",
            "app": "frontend"
        },
        "platformVersion": "eks.8",
        "kubernetesVersion": {
            "major": 1,
            "minor": 30
        }
    }
}
```

Customers could conditionally write policy based on attributes of the cluster.
In this example, the policy denies creating ephemeral containers on pods in clusters with the AWS tag `stage: prod`

```cedar
forbid (
    principal,
    action in k8s::admission::Action::"update",
    resource is core::v1::Pod
) when {
    context has cluster.tags.stage &&
    context.cluster.tags.stage == "prod" &&
    resource.spec has ephemeralContainers
};
```

## Service Control Policies

AWS IAM has a feature called [Service Control Policies (SCP)][scp] that can apply to a whole account or even AWS organization.
These are used by administrators to enforce denial policies like preventing users from disabling AWS GuardDuty, preventing unencrypted uploads to S3, or requiring tags on created resources.

With Cedar, we get decision information for applied policies, giving us the ability to offer an audit mode before switching to an enforcement mode.
We could build this kind of functionality into the project, giving administrators flexible and powerful security controls before turning on a policy that could potentially cause an outage.

[scp]: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html


## Network Policy integration

As Cedar is a flexible language with a customizable schema, it can be applied to many other domains.
One possibility would be integrating Cedar support into a network policy controller.
This would need to use a separate CRD, as it governs network policy instead of cluster access permissions, but needs further exploration.
