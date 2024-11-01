@clusterRoleBinding("kubeadm:get-nodes")
@clusterRole("system:public-info-viewer")
@policyRule("00")
permit (
    principal in k8s::Group::"system:bootstrappers:kubeadm:default-node-token",
    action == k8s::Action::"get",
    resource is k8s::Resource
)
when { resource.apiGroup == "" && resource.resource == "nodes" };