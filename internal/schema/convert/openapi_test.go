package convert

import "testing"

func TestParseSchemaName(t *testing.T) {
	testCases := []struct {
		name                                        string
		intput                                      string
		wantNs, wantAPIGroup, wantVersion, wantKind string
	}{
		{
			"DaemonSet",
			"io.k8s.api.apps.v1.DaemonSet",
			"",
			"apps",
			"v1",
			"DaemonSet",
		},
		{
			"ConfigMap",
			"io.k8s.api.core.v1.ConfigMap",
			"",
			"core",
			"v1",
			"ConfigMap",
		},
		{
			"Cedar Policy",
			"aws.k8s.cedar.v1.Policy",
			"aws::k8s",
			"cedar",
			"v1",
			"Policy",
		},
		{
			"too short",
			"aws.cedar.v1",
			"",
			"",
			"",
			"",
		},
		{
			"Object meta",
			"io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta",
			"",
			"meta",
			"v1",
			"ObjectMeta",
		},
		{
			"CRD",
			"io.cert-manager.v1.ClusterIssuer",
			"io",
			"cert_manager",
			"v1",
			"ClusterIssuer",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotNs, gotAPIGroup, gotVersion, gotKind := ParseSchemaName(tc.intput)
			if gotNs != tc.wantNs {
				t.Fatalf("unexpected ns: got %q, want %q", gotNs, tc.wantNs)
			}
			if gotAPIGroup != tc.wantAPIGroup {
				t.Fatalf("unexpected apigroup: got %q, want %q", gotAPIGroup, tc.wantAPIGroup)
			}
			if gotVersion != tc.wantVersion {
				t.Fatalf("unexpected version: got %q, want %q", gotVersion, tc.wantVersion)
			}
			if gotKind != tc.wantKind {
				t.Fatalf("unexpected kind: got %q, want %q", gotKind, tc.wantKind)
			}
		})
	}
}

func TestSchemaNameToCedar(t *testing.T) {
	cases := []struct {
		name             string
		input            string
		wantNs, wantName string
	}{
		{
			"K8s auth api",
			"io.k8s.api.authentication.v1.TokenRequest",
			"authentication::v1",
			"TokenRequest",
		},
		{
			"K8s autoscaling API",
			"io.k8s.api.autoscaling.v1.Scale",
			"autoscaling::v1",
			"Scale",
		},
		{
			"core K8s api",
			"io.k8s.api.core.v1.ConfigMap",
			"core::v1",
			"ConfigMap",
		},
		{
			"coordination K8s api",
			"io.k8s.api.coordination.v1.Lease",
			"coordination::v1",
			"Lease",
		},
		{
			"k8s meta API",
			"io.k8s.apimachinery.pkg.apis.meta.v1.Status",
			"meta::v1",
			"Status",
		},
		// Should never get this case, we filter it out elsewhere
		// {
		// 	"k8s resoruce API",
		// 	"io.k8s.apimachinery.pkg.api.resource.Quantity",
		// 	"api::resource",
		// 	"Quantity",
		// },
		{
			"Cedar policy resource",
			"aws.k8s.cedar.v1.Policy",
			"aws::k8s::cedar::v1",
			"Policy",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotNs, gotName := SchemaNameToCedar(tc.input)
			if gotNs != tc.wantNs {
				t.Fatalf("unexpected ns: got %q, want %q", gotNs, tc.wantNs)
			}
			if gotName != tc.wantName {
				t.Fatalf("unexpected name: got %q, want %q", gotName, tc.wantName)
			}
		})
	}
}
