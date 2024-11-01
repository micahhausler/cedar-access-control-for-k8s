@ValidatingAdmissionPolicy("service-type.vap-library.com")
@ResourceRule("0")
@Validation("0")
forbid (
    principal,
    action in [k8s::admission::Action::"create", k8s::admission::Action::"update"],
    resource is core::v1::Services
)
when { !(resource.spec has type) && context.params.spec.allowedTypes.contains("ClusterIP") || resource.spec has type && context.params.spec.allowedTypes.contains(resource.spec.type) };