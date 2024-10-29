# Setup

- [Setup](#setup)
  - [Local Setup with Kind](#local-setup-with-kind)
  - [Local Quickstart](#local-quickstart)
  - [Convert RBAC policies](#convert-rbac-policies)

## Local Setup with Kind

To run this project locally, you'll need to install [finch][finch], [Go][go], [kubectl][kubectl], [kind][kind], and [kubebuilder][kubebuilder] (if creating/modifying CRDs).

[finch]: https://github.com/runfinch/finch
[go]: https://go.dev/dl
[kubectl]: https://kubernetes.io/docs/tasks/tools/
[kind]: https://kind.sigs.k8s.io/
[kubebuilder]: https://book.kubebuilder.io/quick-start

To install `kind` that works with `finch` and supports Kubernetes v1.31, you need at least v0.24.0:
```bash
go install sigs.k8s.io/kind@v0.24.0
# ensure $GOPATH/bin is in your $PATH
kind --version
# kind version 0.24.0
```

Then ensure you have a `finch` VM build
```bash
finch version
finch vm start
```

## Local Quickstart

1. For an optional local build of the binaries, you can run:
    ```bash
    make build
    ```
2. Start the Kind cluster
    This will build the webhook image, the Kind image, and create the Kind cluster.
    This cluster is configured to authorize and validate requests via the Cedar webhook:
   ```bash
   make kind
   ```
3. Create policies. There's an example in `demo/authorization-policy.yaml` that is auto-created, but feel free to modify it or create more
   ```bash
   # edit demo/authorization-policy.yaml
   kubectl apply -f demo/authorization-policy.yaml
   ```
4. Now you can make requests! You'll need use the generated kubeconfig `./mount/test-user-kubeconfig.yam` created in step 6. The user has the name `test-user` with the group `test-group`. Your default kubeconfig (`~/.kube/config`) will be auto-configured by kind with a cluster administrator identity, so `kubectl` without specifying a kubeconfig should always just work.
    ```bash
    # Lookup the username you are testing
    KUBECONFIG=./mount/test-user-kubeconfig.yaml kubectl auth whoami

    # Try getting resources
    KUBECONFIG=./mount/test-user-kubeconfig.yaml kubectl get pods --all-namespaces # allowed
    KUBECONFIG=./mount/test-user-kubeconfig.yaml kubectl get nodes # denied

    # Attribute-based label selection example
    KUBECONFIG=./mount/test-user-kubeconfig.yaml kubectl get secrets # denied
    KUBECONFIG=./mount/test-user-kubeconfig.yaml kubectl get secrets -l owner=test-user --show-labels # allowed

    # As admin, list secrets
    kubectl get secrets --show-labels

    # Impersonation
    KUBECONFIG=./mount/test-user-kubeconfig.yaml kubectl get service \
        --as system:serviceaccount:default:service-manager
    ```
5. Try out admission policies:
    ```bash
    # (Optional) Update the validating webhook API groups/versions/resources you want validated
    # by edting manifests/admission-webhook.yaml before applying the webhook

    make admission-webhook

    # Apply an example admission policy
    kubectl apply -f demo/admission-policy.yaml

    # Create sample user in requires-labels group
    make sample-user-kubeconfig
    KUBECONFIG=./mount/sample-user-kubeconfig.yaml kubectl auth whoami

    # Try to create a configmap without labels as the sample user
    KUBECONFIG=./mount/sample-user-kubeconfig.yaml kubectl create configmap test-config --from-literal=k1=v1
    KUBECONFIG=./mount/sample-user-kubeconfig.yaml kubectl get configmap

    # Create a configmap as the sample user with the label owner={principal.name}
    cat << EOF > sample-config.yaml
    apiVersion: v1
    kind: ConfigMap
    metadata:
        name: sample-config
        labels:
            owner: sample-user
    data:
        stage: test
    EOF
    KUBECONFIG=./mount/sample-user-kubeconfig.yaml kubectl create -f ./sample-config.yaml
    KUBECONFIG=./mount/sample-user-kubeconfig.yaml kubectl get configmap -l owner=sample-user --show-labels
    ```

And for teardown/cleanup:
```bash
make clean-kind
```

## Convert RBAC policies

There's an RBAC converter that works on ClusterRoleBindings or RoleBindings.
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
