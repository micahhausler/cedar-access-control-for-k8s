forbid ( principal, action, resource )
when { if resource.spec.replicas > 5 then "yes" else "no" };