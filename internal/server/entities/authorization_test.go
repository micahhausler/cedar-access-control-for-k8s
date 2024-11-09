package entities_test

import (
	"testing"

	"github.com/awslabs/cedar-access-control-for-k8s/internal/server/entities"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestResourceRequestToPath(t *testing.T) {
	cases := []struct {
		name  string
		input authorizer.Attributes
		want  string
	}{
		{
			name: "cluster pod list",
			input: &authorizer.AttributesRecord{
				Resource:   "pods",
				APIVersion: "v1",
				APIGroup:   "",
			},
			want: "/api/v1/pods",
		},
		{
			name: "namespaced apiGroup, named",
			input: &authorizer.AttributesRecord{
				Resource:   "deployments",
				APIVersion: "v1",
				APIGroup:   "apps",
				Namespace:  "kube-system",
				Name:       "coredns",
			},
			want: "/apis/apps/v1/namespaces/kube-system/deployments/coredns",
		},
		{
			name: "subresource",
			input: &authorizer.AttributesRecord{
				Resource:    "pods",
				APIVersion:  "v1",
				APIGroup:    "",
				Namespace:   "default",
				Name:        "mypod",
				Subresource: "logs",
			},
			want: "/api/v1/namespaces/default/pods/mypod/logs",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := entities.ResourceRequestToPath(tc.input)
			if got != tc.want {
				t.Errorf("wanted %s, got %s", tc.want, got)
			}
		})
	}
}
