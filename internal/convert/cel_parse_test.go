package convert

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/cedar-policy/cedar-go"
	cedarast "github.com/cedar-policy/cedar-go/ast"
	"github.com/google/cel-go/cel"
	"github.com/google/go-cmp/cmp"
)

func TestWalk(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		wantErr    error
		goldenFile string
	}{
		{
			name:       "long and bool",
			input:      `object.spec.priority > 1000000 && object.spec.hostNetwork == false`,
			goldenFile: "long-and-bool.cedar",
		},
		{
			name:       "simple has and has",
			input:      `has(object.spec) && has(object.spec.targetNamespace) `,
			goldenFile: "simple-has-and-has.cedar",
		},
		{
			name:       "Simple set presence",
			input:      `has(object.spec.type) && object.spec.type in ["ClusterIP", "NodePort"]`,
			goldenFile: "simple-set-presence.cedar",
		},
		{
			name:       "CEL startswith",
			input:      `object.meta.name.startsWith("hello")`,
			goldenFile: "cel-startswith.cedar",
		},
		{
			name:       "CEL endswith",
			input:      `object.meta.name.endsWith("hello")`,
			goldenFile: "cel-endswith.cedar",
		},
		{
			name:       "CEL string contains",
			input:      `object.meta.labels.owner.contains("k8s.io/node-")`,
			goldenFile: "cel-string-contains.cedar",
		},
		{
			name:       "ternary",
			input:      `(object.spec.replicas > 5) ? 'yes' : 'no'`,
			goldenFile: "cel-ternary.cedar",
		},
		{
			name:       "addition",
			input:      `object.spec.replicas - 1  == 1 + 2`,
			goldenFile: "cel-addition.cedar",
		},
		{
			name:  "decimal less than",
			input: `3.14 + 1.86 < 6.0`,
			// TODO: should be `.lessThan(decimal("6.0"))`, but
			// the AST packages don't contain enough information yet
			goldenFile: "cel-decimal-lt.cedar",
		},
		{
			name:       "list membership",
			input:      `2 in [1, 2, 3]`,
			goldenFile: "cel-list-membership.cedar",
		},
		{
			name:       "map construction",
			input:      `{'key': 'k1', 'value': 'v1'} in object.meta.labels`,
			goldenFile: "struct-conversion.cedar",
		},
		{
			name:  "byte string",
			input: `object.meta.name == b"über" && object.meta.namespace == "\303\277"`,
			// wantErr: fmt.Errorf("cedar doesn't support byte strings"),
			goldenFile: "cel-byte-strings.cedar",
		},
		// Not implemented
		{
			name:    "cel double conversion",
			input:   `double("3.14")`,
			wantErr: fmt.Errorf("cedar-go AST package doesn't yet support decimal() conversion: requires manual translation"),
		},
		{
			name:    "all failure cases",
			input:   `object.spec.volumes.all(volume, has(volume.configMap) || has(volume.secret))`,
			wantErr: fmt.Errorf("cedar doesn't support comprehensions"),
		},
		{
			name:    "division",
			input:   `object.spec.replicas == 9/3`,
			wantErr: fmt.Errorf("cedar doesn't support division"),
		},
		{
			name:    "cel exists",
			input:   `[1, 2, 3].exists(i, i % 2 != 0)`,
			wantErr: fmt.Errorf("cedar doesn't support comprehensions"),
		},
		{
			name:    "list indexing",
			input:   `object.meta.finalizers[0] == 'kubernetes'`,
			wantErr: fmt.Errorf("cedar doesn't support array indexing"),
		},
		{
			name:    "RE2 matcher",
			input:   `object.meta.name.matches('^[a-zA-Z]*$')`,
			wantErr: fmt.Errorf("cedar doesn't support RE2 matching"),
		},
		{
			name:    "struct construction",
			input:   `google.protobuf.Struct{}`,
			wantErr: fmt.Errorf("struct not yet implemented"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, err := cel.NewEnv(
				cel.Variable("object", cel.AnyType),
				cel.Variable("params", cel.AnyType),
			)
			if err != nil {
				t.Fatalf("Failed to create environment: %v", err)
			}

			ast, issues := env.Compile(tc.input)
			if issues != nil && issues.Err() != nil {
				t.Fatalf("Compilation error: %v", issues.Err())
			}

			node, err := walkAST(ast.NativeRep().Expr())
			if err != nil {
				if tc.wantErr != nil {
					if err.Error() == tc.wantErr.Error() {
						return
					}
					t.Fatalf("Expected error %v, got %v", tc.wantErr, err)
				}
				t.Fatalf("Error walking cel tree: %v", err)
			}
			if tc.wantErr != nil {
				t.Fatalf("Expected error %v, got nil error", tc.wantErr)
			}

			rawPolicy := cedarast.Forbid()
			if node != nil {
				rawPolicy = rawPolicy.When(*node)
			}

			policy := cedar.NewPolicyFromAST(rawPolicy)
			goldenFile := "celtestdata/" + tc.goldenFile
			if *update {
				t.Logf("updating testdata golden file %s", goldenFile)
				if err := os.WriteFile(goldenFile, policy.MarshalCedar(), 0644); err != nil {
					t.Fatalf("failed to update testdata golden file %s: %s", goldenFile, err)
				}
			}

			data, err := os.ReadFile(goldenFile)
			if err != nil {
				t.Fatalf("Error reading golden file: %v", err)
			}

			wantPl, err := cedar.NewPolicyListFromBytes(goldenFile, data)
			if err != nil {
				t.Fatalf("Error parsing golden file: %v", err)
			}
			if len(wantPl) != 1 {
				t.Fatalf("Expected 1 policy in golden file, got %d", len(wantPl))
			}

			if !bytes.Equal(wantPl[0].MarshalCedar(), policy.MarshalCedar()) {
				t.Errorf("Did not get desired polcy: %s", cmp.Diff(
					string(wantPl[0].MarshalCedar()),
					string(policy.MarshalCedar()),
				))
			}

		})
	}
}
