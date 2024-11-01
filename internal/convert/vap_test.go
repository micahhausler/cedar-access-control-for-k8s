package convert

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/google/go-cmp/cmp"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/yaml"
)

const vap = `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: "demo-policy.example.com"
spec:
  failurePolicy: Fail
  paramKind:
    kind: ConfigMap
	apiVersion: v1
  matchConstraints:
    namespaceSelector:
      matchLabels:
        environment: test
	objectSelector:
	  matchLabels:
	    app: demo # equiv to matchExpressions: [{key: app, operator: In, values: [demo]}]
	  matchExpressions:
	    - key: tier
		  operator: In # In, NotIn, Exists, DoesNotExist
		  values: [frontend, backend]
    resourceRules:
    - apiGroups:   ["apps"] # required, can be '*'
      apiVersions: ["v1"] # required, can be '*'
      operations:  ["CREATE", "UPDATE"] # required, create/update/delete/connect/*
      resources:   ["deployments"] # required, can be '*', '*/*' means all subresources
	  resourceNames: ["demo-deploy"] # optional
	  scope: "Namespaced" # optional, defaults to "*", can be "Cluster"
	# excludeResourceRules: inverse of resource rules, takes prescidence over resourceRules
	matchPolicy: "Equivalent" # optional, defaults to "Equivalent", can be "Exact". 
  validations:
    - expression: "object.spec.replicas <= 5"
	  message: "Replicas must be less than or equal to 5"
	  reason: "Forbidden"
	  messageExpression: "object.x must be less than max (\"+string(params.max)+\")"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: "demo-binding-test.example.com"
spec:
  policyName: "demo-policy.example.com"
  validationActions: [Deny]
  paramRef: # optional
	name: 
  matchResources: # same as matchConstraints, but for the binding
    namespaceSelector:
      matchLabels:
        environment: test
`

func TestVapToCedar(t *testing.T) {
	cases := []struct {
		name       string
		inputFile  string
		goldenFile string
		wantError  bool
	}{
		{
			name:       "service types",
			inputFile:  "service-types.yaml",
			goldenFile: "service-types.cedar",
			wantError:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inputFile := filepath.Join("vaptestdata", tc.inputFile)
			goldenFile := filepath.Join("vaptestdata", tc.goldenFile)
			data, err := os.ReadFile(inputFile)
			if err != nil {
				t.Fatalf("failed to read testdata input file %s: %s", inputFile, err)
			}
			vap := &admissionregistrationv1.ValidatingAdmissionPolicy{}
			err = yaml.Unmarshal(data, vap)
			if err != nil {
				t.Fatalf("failed to unmarshal testdata input file %s: %s", inputFile, err)
			}

			got, err := VapToCedar(vap)
			if (err != nil) != tc.wantError {
				t.Errorf("VAPToCedar(%q) error = %v, wantError %v", inputFile, err, tc.wantError)
				return
			}

			if *update {
				t.Logf("updating testdata golden file %s", goldenFile)
				if err := os.WriteFile(goldenFile, got.MarshalCedar(), 0644); err != nil {
					t.Fatalf("failed to update testdata golden file %s: %s", goldenFile, err)
				}
			}
			want, err := os.ReadFile(goldenFile)
			if err != nil {
				t.Fatalf("failed to read testdata golden file %s: %s", tc.goldenFile, err)
			}

			wantPS, err := cedar.NewPolicySetFromBytes(goldenFile, want)
			if err != nil {
				t.Fatalf("failed to parse testdata golden file %s: %s", goldenFile, err)
			}
			if !bytes.Equal(wantPS.MarshalCedar(), got.MarshalCedar()) {
				t.Errorf("Did not get desired polcy: %s", cmp.Diff(
					string(wantPS.MarshalCedar()),
					string(got.MarshalCedar()),
				))
			}
		})
	}
}
