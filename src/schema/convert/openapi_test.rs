use crate::schema::convert::openapi::parse_schema_name;

#[test]
fn test_parse_schema_name() {
    struct TestCase {
        name: &'static str,
        input: &'static str,
        want_ns: String,
        want_api_group: String,
        want_version: String,
        want_kind: String,
    }

    let test_cases = vec![
        TestCase {
            name: "DaemonSet",
            input: "io.k8s.api.apps.v1.DaemonSet",
            want_ns: "".to_string(),
            want_api_group: "apps".to_string(),
            want_version: "v1".to_string(),
            want_kind: "DaemonSet".to_string(),
        },
        TestCase {
            name: "ConfigMap",
            input: "io.k8s.api.core.v1.ConfigMap",
            want_ns: "".to_string(),
            want_api_group: "core".to_string(),
            want_version: "v1".to_string(),
            want_kind: "ConfigMap".to_string(),
        },
        TestCase {
            name: "Cedar Policy",
            input: "aws.k8s.cedar.v1.Policy",
            want_ns: "aws::k8s".to_string(),
            want_api_group: "cedar".to_string(),
            want_version: "v1".to_string(),
            want_kind: "Policy".to_string(),
        },
        TestCase {
            name: "too short",
            input: "aws.cedar.v1",
            want_ns: "".to_string(),
            want_api_group: "".to_string(),
            want_version: "".to_string(),
            want_kind: "".to_string(),
        },
        TestCase {
            name: "Object meta",
            input: "io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta",
            want_ns: "".to_string(),
            want_api_group: "meta".to_string(),
            want_version: "v1".to_string(),
            want_kind: "ObjectMeta".to_string(),
        },
        TestCase {
            name: "CRD",
            input: "io.cert-manager.v1.ClusterIssuer",
            want_ns: "io".to_string(),
            want_api_group: "cert_manager".to_string(),
            want_version: "v1".to_string(),
            want_kind: "ClusterIssuer".to_string(),
        },
    ];

    for tc in test_cases {
        let (got_ns, got_api_group, got_version, got_kind) = parse_schema_name(tc.input);
        
        assert_eq!(got_ns, tc.want_ns, "{}: unexpected ns: got {}, want {}", 
            tc.name, got_ns, tc.want_ns);
        assert_eq!(got_api_group, tc.want_api_group, "{}: unexpected api_group: got {}, want {}", 
            tc.name, got_api_group, tc.want_api_group);
        assert_eq!(got_version, tc.want_version, "{}: unexpected version: got {}, want {}", 
            tc.name, got_version, tc.want_version);
        assert_eq!(got_kind, tc.want_kind, "{}: unexpected kind: got {}, want {}", 
            tc.name, got_kind, tc.want_kind);
    }
} 