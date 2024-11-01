forbid ( principal, action, resource )
when { resource.spec has type && ["ClusterIP", "NodePort"].contains(resource.spec.type) };