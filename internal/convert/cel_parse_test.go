package convert

import (
	"bytes"
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

			node, err := walkAST(ast.NativeRep().Expr(), 0)
			if err != nil {
				t.Fatalf("Error walking cel tree: %v", err)
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
