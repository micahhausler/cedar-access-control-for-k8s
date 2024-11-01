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