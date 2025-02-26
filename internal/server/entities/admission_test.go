package entities

import (
	"net/netip"
	"testing"

	cedartypes "github.com/cedar-policy/cedar-go/types"
	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestUnstructuredToEntity(t *testing.T) {
	cases := []struct {
		name        string
		input       any
		expected    cedartypes.Record
		expectedErr error
	}{
		{
			name: "valid pod",
			input: &corev1.Pod{
				TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
				ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{ // slice
						{
							Name:  "test-container", // string
							Image: "test-image",
						},
					},
					NodeName:              "test-node",
					HostNetwork:           true,                                     // true bool
					ShareProcessNamespace: func() *bool { var b bool; return &b }(), // false bool pointer
				},
				Status: corev1.PodStatus{
					Phase: "Running",
					PodIP: "10.10.1.4", // ip type
				},
			},
			expected: cedartypes.NewRecord(cedartypes.RecordMap{
				cedartypes.String("apiVersion"): cedartypes.String("v1"),
				cedartypes.String("kind"):       cedartypes.String("Pod"),
				cedartypes.String("metadata"): cedartypes.NewRecord(cedartypes.RecordMap{
					cedartypes.String("name"):      cedartypes.String("test-pod"),
					cedartypes.String("namespace"): cedartypes.String("default"),
				}),
				cedartypes.String("spec"): cedartypes.NewRecord(cedartypes.RecordMap{
					cedartypes.String("containers"): cedartypes.NewSet(
						cedartypes.NewRecord(cedartypes.RecordMap{
							cedartypes.String("name"):  cedartypes.String("test-container"),
							cedartypes.String("image"): cedartypes.String("test-image"),
						})),
					cedartypes.String("nodeName"):              cedartypes.String("test-node"),
					cedartypes.String("hostNetwork"):           cedartypes.Boolean(true),
					cedartypes.String("shareProcessNamespace"): cedartypes.Boolean(false),
				}),
				cedartypes.String("status"): cedartypes.NewRecord(cedartypes.RecordMap{
					cedartypes.String("phase"): cedartypes.String("Running"),
					cedartypes.String("podIP"): cedartypes.IPAddr(netip.MustParsePrefix("10.10.1.4/32")),
				}),
			}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unstMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.input)
			if err != nil {
				t.Fatalf("failed to convert input to unstructured: %v", err)
			}
			unst := &unstructured.Unstructured{Object: unstMap}
			got, err := UnstructuredToRecord(unst, "core", "v1", "Pod")
			if err != nil {
				if tc.expectedErr == nil {
					t.Fatalf("got unexpected error. wanted %v, got %v", tc.expectedErr, err)
				}
			}
			if diff := cmp.Diff(tc.expected, got); diff != "" {
				t.Errorf("unexpected output (-want +got):\n%s", diff)
				actualJSON, _ := got.MarshalJSON()
				expectedJSON, _ := tc.expected.MarshalJSON()
				t.Errorf("expected: %s", string(expectedJSON))
				t.Errorf("actual:   %s", string(actualJSON))
			}
		})
	}
}
