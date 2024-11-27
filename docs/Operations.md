# Operating the Cedar Webhook

> **WARNING**: As stated in the README, while Cedar is a production-ready policy language, this project is still in active development and not yet intended for production use.
> The Kubernetes Custom Resource Definitions (CRDs) and Cedar schemas used in this project are not solidified and highly subject to change.

## Server initialization

There is an inherent circular dependency when using CRD-based policies, so the Cedar webhook makes tradeoffs to get around this issue.

1. The Kubernetes API server tries to read a kubeconfig-formatted file containing connection information of the authorizing webhook. 
   If that file is not available, the API server crashes and restarts. 
   Once the file is available and populated, the API server attempts to authorize requests against that webhook.
   For demonstration purposes, we set the API server's client timeout to 3s with a failure policy of `NoOpinion` if the webhook is not serving requests yet.
2. When the cedar-webhook process starts, it looks for a [store configuration file](#multiple-tiered-policy-store-configuration) to look up policies.
   The authorizer returns a `NoOpinion` decision until all policy stores are reported as initialized.
   The admission webhook returns an allow decision until all policy stores are reported as initialized.
   1. For the CRD policy store, the store configuration sleeps and retries until the `KUBECONFIG`-specified file is present and populated.
   2. The Directory store reads a given directory for all files ending in `.cedar`. 
    It is ready after first read.
   3. The Amazon Verified Permission policy store uses whatever configured AWS credentials are provided in the default credential chain (environment variables, shared config file, IMDS, etc.) 
3. The provided `Makefile` includes a step that creates a kubeconfig with a client certificate for the identity `system:authorizer:cedar-authorizer` in the `system:authorizers` group.
    Once completed and consumed by the CRD policy store, it is marked as initialized.
    The authorization webhook returns a hard-coded allow for any read request to any Cedar Policy CRD API `cedar.k8s.aws` Policy resource or RBAC resource.
4. Once all policy stores are loaded, the webhook starts to evaluate requests

## Multiple Tiered Policy Store Configuration

Cedar for Kubernetes supports reading from multiple policy stores through a configuration file.
The file is specified through the `--config` flag to the cedar-webhook process.

```yaml
apiVersion: cedar.k8s.aws/v1alpha1
kind: StoreConfig
spec:
  stores:
    - type: "directory"
      directoryStore:
        path: "/cedar-authorizer/priority-policies"
        refreshInterval: 60m  # optional: defaults to 1m
    - type: "directory"
      directoryStore:
        path: "/cedar-authorizer/converted-policies"
        refreshInterval: 24h  # optional: defaults to 1m
    - type: "verifiedPermissions"
      verifiedPermissionsStore:
        policyStoreId: "F1GpuaUkZYeas3B8TBcXRj"
        refreshInterval: 4m          # optional: defaults to 5m
        # awsRegion: "us-west-2"     # optional: uses default chain otherwise
        # awsProfile: "profile_name" # optional: uses default profile otherwise
    - type: "crd"
        # kubeconfigContext: "" # optional: an alternate kubeconfig context to connect to a different API server
```

Policy stores are evaluated first to last, returning the result for the first explicit policy found in any policy store.
If no explicit policies apply to a request, the webhook moves to the next policy store.
For authorization requests, if no explicit policies match in the final policy store, the request is denied by default.
For admission requests, the webhook implicitly adds a final store with a single policy that permits all admission actions by default.
As always for Cedar within a policy store, `forbid` policies take precedence over `permit`. Be aware that a matching `permit` in an earlier policy store will be always be returned even if there are explicitly matching `forbid` policies in later policy stores.

> **Note:** A global forbid policy such as `forbid(principal, action, resource);` can still be written at any tier and adversely affect a cluster. Take care in the policies you write to ensure they don't disrupt cluster operations.

In real-world deployments, you may want to consider a strategy using the following tiers:

1. Highly trusted policies in a central policy store, either Amazon Verified permissions or a static directory
2. Converted policies for built-in RBAC rules, allowing controllers and other resources to function correctly
4. User-defined policies in CRDs in a cluster

## Admission webhook configuration

The validating admission webhook configuration in the repository currently applies to all apiGroups, versions, resources, and subresources. 
If you find that there are API groups, versions, or resources you wish not to be governed by Cedar, you can configure the `rules` or [ `matchConditions`][match-conditions] on the webhook.

[match-conditions]: https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#matching-requests-matchconditions

## Authorization webhook configuration 

The provided [example authorization webhook config](/mount/authorization-config.yaml) for the Kubernetes API server is not configured for production use.
Be sure to evaluate all authorization webhook options and consult Kubernetes documentation before running in a real environment.

## Static pod manifest

The provided [static pod manifest](/manifests/cedar-authorization-webhook.yaml) is for demonstration purposes and configured to run in Kind only. 
You will need to evaluate resource requests and limits, security configuration and image policies for your environment. 
