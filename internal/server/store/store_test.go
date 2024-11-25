package store_test

import (
	"encoding/json"
	"testing"

	"github.com/awslabs/cedar-access-control-for-k8s/internal/server/store"
	"github.com/cedar-policy/cedar-go"
	cedartypes "github.com/cedar-policy/cedar-go/types"
	"github.com/google/go-cmp/cmp"
)

func NewStoreFromPolicy(policy string) store.PolicyStore {
	mStore, err := store.NewMemoryStore("in-memory-test-store.cedar", []byte(policy), true)
	if err != nil {
		panic(err)
	}
	return mStore
}

func TestTieredIsAuthorized(t *testing.T) {

	entities := cedartypes.EntityMap{
		cedartypes.EntityUID{
			Type: "k8s::User",
			ID:   "alice",
		}: cedar.Entity{
			UID: cedartypes.EntityUID{
				Type: "k8s::User",
				ID:   "alice",
			},
			Attributes: cedartypes.NewRecord(map[cedartypes.String]cedartypes.Value{
				"name": cedartypes.String("alice"),
			}),
			Parents: cedartypes.NewEntityUIDSet(
				cedartypes.EntityUID{
					Type: "k8s::Group",
					ID:   "admin",
				},
			),
		},
		cedartypes.EntityUID{
			Type: "k8s::Group",
			ID:   "admin",
		}: cedar.Entity{
			UID: cedartypes.EntityUID{
				Type: "k8s::Group",
				ID:   "admin",
			},
			Attributes: cedartypes.NewRecord(map[cedartypes.String]cedartypes.Value{
				"name": cedartypes.String("admin"),
			}),
		},
		cedartypes.EntityUID{
			Type: "k8s::Resource",
			ID:   "/api/v1/namespaces/default/configmaps/cm1",
		}: cedar.Entity{
			UID: cedartypes.EntityUID{
				Type: "k8s::Resource",
				ID:   "/api/v1/namespaces/default/configmaps/cm1",
			},
			Attributes: cedartypes.NewRecord(map[cedartypes.String]cedartypes.Value{
				"name":      cedartypes.String("cm1"),
				"namespace": cedartypes.String("default"),
				"apiGroup":  cedartypes.String(""),
				"resource":  cedartypes.String("configmaps"),
			}),
		},
	}

	cases := []struct {
		name     string
		stores   store.TieredPolicyStores
		req      cedartypes.Request
		want     cedar.Decision
		wantDiag cedar.Diagnostic
	}{
		{
			name: "tiered policies allow over deny",
			stores: store.TieredPolicyStores{
				NewStoreFromPolicy(`permit(principal in k8s::Group::"admin", action, resource);`),
				NewStoreFromPolicy(`forbid(principal in k8s::Group::"admin", action, resource);`),
			},
			req: cedartypes.Request{
				Principal: cedartypes.EntityUID{
					Type: "k8s::User",
					ID:   "alice",
				},
				Action: cedartypes.EntityUID{
					Type: "k8s::Action",
					ID:   "get",
				},
				Resource: cedartypes.EntityUID{
					Type: "k8s::Resource",
					ID:   "/api/v1/namespaces/default/configmaps/cm1",
				},
			},
			want: cedar.Allow,
			wantDiag: cedar.Diagnostic{
				Reasons: []cedartypes.DiagnosticReason{
					{
						PolicyID: "policy0",
						Position: cedartypes.Position{Filename: "in-memory-test-store.cedar", Offset: 0, Line: 1, Column: 1},
					},
				},
			},
		},
		{
			name: "tiered default deny",
			stores: store.TieredPolicyStores{
				NewStoreFromPolicy(`forbid(principal, action == k8s::Action::"list", resource);`),
				NewStoreFromPolicy(`forbid(principal in k8s::Group::"read-only", action, resource);`),
			},
			req: cedartypes.Request{
				Principal: cedartypes.EntityUID{
					Type: "k8s::User",
					ID:   "alice",
				},
				Action: cedartypes.EntityUID{
					Type: "k8s::Action",
					ID:   "get",
				},
				Resource: cedartypes.EntityUID{
					Type: "k8s::Resource",
					ID:   "/api/v1/namespaces/default/configmaps/cm1",
				},
			},
			want:     cedar.Deny,
			wantDiag: cedar.Diagnostic{},
		},
		{
			name: "tiered default allow",
			stores: store.TieredPolicyStores{
				NewStoreFromPolicy(`forbid(principal, action == k8s::Action::"list", resource);`),
				NewStoreFromPolicy(`forbid(principal in k8s::Group::"read-only", action, resource);`),
				NewStoreFromPolicy(`permit(principal, action, resource);`),
			},
			req: cedartypes.Request{
				Principal: cedartypes.EntityUID{
					Type: "k8s::User",
					ID:   "alice",
				},
				Action: cedartypes.EntityUID{
					Type: "k8s::Action",
					ID:   "get",
				},
				Resource: cedartypes.EntityUID{
					Type: "k8s::Resource",
					ID:   "/api/v1/namespaces/default/configmaps/cm1",
				},
			},
			want: cedar.Allow,
			wantDiag: cedar.Diagnostic{
				Reasons: []cedartypes.DiagnosticReason{
					{
						PolicyID: "policy0",
						Position: cedartypes.Position{Filename: "in-memory-test-store.cedar", Offset: 0, Line: 1, Column: 1},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {

			decision, diagnostic := tc.stores.IsAuthorized(entities, tc.req)

			if decision != tc.want {
				t.Fatalf("got %v, want %v", decision, tc.want)
			}

			gotDiag, err := json.MarshalIndent(diagnostic, "", "  ")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			wantDiag, err := json.MarshalIndent(tc.wantDiag, "", "  ")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !cmp.Equal(gotDiag, wantDiag) {
				t.Fatalf("diagnostic mismatch (-want +got):\n%s", cmp.Diff(wantDiag, gotDiag))
			}
		})
	}

}
