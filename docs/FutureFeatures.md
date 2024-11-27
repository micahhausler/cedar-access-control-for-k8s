# Potential Future Feature Ideas

The following list of feature ideas are not yet built, but potential candidates for addition.

## RBAC-converted policy store

While RBAC continues to function in a cluster configured with Cedar, it typically is configured as a Kubernetes Authorizer after a Webhook authorizer like Cedar so that Cedar `forbid` policies have precedence over RBAC rules. 

Many in-tree controllers (scheduler, kube-controller-manager, etc) rely on RBAC for authorization, and it is possible to write a forbid Cedar policy such as `forbid(principal, action, resource);` that can prevent a cluster from working.

Rather than forcing users to convert RBAC policies to Cedar and configure a store with those policies, we could build a policy store that reads RBAC policies and converts them into Cedar policies as a named policy store.

```yaml
apiVersion: cedar.k8s.aws/v1alpha1
kind: StoreConfig
spec:
  stores:
    - type: "directory"
      directoryStore:
        path: "/cedar-authorizer/priority-policies"
    - type: "rbac"
      rbacStore:
        selector: # key/value labels to filter for on startup
            kubernetes.io/bootstrapping: rbac-defaults  
        requiredAnnotations: # required annotations of any RBAC resource to convert
            rbac.authorization.kubernetes.io/autoupdate: "true"
    - type: "crd" # CRD-authored policies come after RBAC-converted policies
```

This could be either once at startup, or rely on a watch cache to auto-update. 
If this were implemented, anyone with permission to create an RBAC policy could potentially create RBAC policies that could be enforced ahead of CRD-based `forbid` policies. 
Care will need to be taken to ensure that only cluster-required RBAC policies are converted. 
This could be either through a label selector/required annotations list as called out above, or through a static list of known policy names, or even bake in RBAC policies into the authorizer (along with the K8s version). 

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
