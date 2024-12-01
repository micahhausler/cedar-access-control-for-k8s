package convert

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/google/go-cmp/cmp"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

func TestRoleBindingToCedar(t *testing.T) {
	// TODO: add all of Kind's in-cluster roles/roleBindings

	testCases := []string{"system:controller:token-cleaner"}

	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			yamlName := filepath.Join("testdata", tc+".yaml")
			_, err := os.Stat(yamlName)
			if err != nil {
				t.Fatalf("failed to stat testdata file %s: %s", yamlName, err)
			}

			rb := rbacv1.RoleBinding{}
			rr := rbacv1.Role{}

			yamlData, err := os.ReadFile(yamlName)
			if err != nil {
				t.Fatalf("failed to open testdata file %s: %s", yamlName, err)
			}
			decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewBuffer(yamlData), 1024)
			err = decoder.Decode(&rb)
			if err != nil {
				t.Fatalf("failed to decode testdata file %s: %s", yamlName, err)
			}
			err = decoder.Decode(&rr)
			if err != nil && !errors.Is(err, io.EOF) {
				t.Fatalf("failed to decode testdata file %s: %s", yamlName, err)
			}

			ps := RoleBindingToCedar(rb, rr)

			testdata := filepath.Join("testdata", tc+".cedar")
			if *update {
				t.Logf("updating testdata golden file %s", testdata)
				if err := os.WriteFile(testdata, ps.MarshalCedar(), 0644); err != nil {
					t.Fatalf("failed to update testdata golden file %s: %s", testdata, err)
				}
			}
			want, err := os.ReadFile(testdata)
			if err != nil {
				t.Fatalf("failed to read testdata golden file %s: %s", testdata, err)
			}

			wantPS, err := cedar.NewPolicySetFromBytes(tc+".cedar", want)
			if err != nil {
				t.Fatalf("failed to parse testdata golden file %s: %s", testdata, err)
			}
			if !bytes.Equal(wantPS.MarshalCedar(), ps.MarshalCedar()) {
				t.Errorf("Did not get desired polcy: %s", cmp.Diff(
					string(wantPS.MarshalCedar()),
					string(ps.MarshalCedar()),
				))
			}

		})

	}
}
