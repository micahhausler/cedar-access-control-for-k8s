use kube::core::GroupVersionKind;


pub fn gvk_to_cedar(gvk: &GroupVersionKind) -> String {
    let sanitized_group = gvk.group.clone().replace("-", "_");
    let group_parts: Vec<&str> = sanitized_group.split('.').collect();

    let mut parts: Vec<&str> = vec![];

    match sanitized_group.len() {
        0 => parts.push("core"),
        _ => {
            parts.extend(group_parts.iter().rev());
        }
    }

    parts.push(gvk.version.as_str());
    parts.push(gvk.kind.as_str());

    parts.join("::")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gvk_to_cedar() {
        // Test k8s API case
        let test_cases = vec![
            (
                "core api group",
                GroupVersionKind {
                    group: "".to_string(),
                    version: "v1".to_string(), 
                    kind: "Pod".to_string()
                },
                "core::v1::Pod"
            ),
            (
                "apps api group",
                GroupVersionKind {
                    group: "apps".to_string(),
                    version: "v1".to_string(),
                    kind: "Deployment".to_string()
                },
                "apps::v1::Deployment"
            ),
            (
                "custom resource",
                GroupVersionKind {
                    group: "cedar.k8s.aws".to_string(),
                    version: "v1alpha1".to_string(),
                    kind: "Policy".to_string()
                },
                "aws::k8s::cedar::v1alpha1::Policy"
            ),
            (
                "group with hyphens",
                GroupVersionKind {
                    group: "my-domain.my-company.com".to_string(),
                    version: "v1".to_string(),
                    kind: "Resource".to_string()
                },
                "com::my_company::my_domain::v1::Resource"
            )
        ];

        for (name, input, expected) in test_cases {
            assert_eq!(gvk_to_cedar(&input), expected, "Failed test case: {}", name);
        }
    }

} 