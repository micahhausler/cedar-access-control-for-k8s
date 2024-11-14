package store

import (
	"context"
	"sync"

	cedarv1alpha1 "github.com/awslabs/cedar-access-control-for-k8s/api/v1alpha1"
	"github.com/cedar-policy/cedar-go"
	"k8s.io/apimachinery/pkg/runtime"
	uitlruntime "k8s.io/apimachinery/pkg/util/runtime"
)

var (
	scheme *runtime.Scheme = runtime.NewScheme()
)

func init() {
	uitlruntime.Must(cedarv1alpha1.AddToScheme(scheme))
}

type PolicyStore interface {
	// InitalPolicyLoadComplete signals if authorizer is ready to authorize requests
	// While this is false, the authorizer will emit a k8sauthorizer.NoOpinion until its ready
	InitalPolicyLoadComplete() bool
	PolicySet(context.Context) *cedar.PolicySet
	Name() string
}

type unifiedStore struct {
	initalPolicyLoadComplete   bool
	initalPolicyLoadCompleteMu sync.RWMutex

	stores []PolicyStore
}

func (u *unifiedStore) InitalPolicyLoadComplete() bool {
	u.initalPolicyLoadCompleteMu.RLock()
	if u.initalPolicyLoadComplete {
		u.initalPolicyLoadCompleteMu.RUnlock()
		return true
	}
	u.initalPolicyLoadCompleteMu.RUnlock()

	for _, store := range u.stores {
		if !store.InitalPolicyLoadComplete() {
			return false
		}
	}
	u.initalPolicyLoadCompleteMu.Lock()
	defer u.initalPolicyLoadCompleteMu.Unlock()
	u.initalPolicyLoadComplete = true
	return true
}

func (u *unifiedStore) PolicySet(ctx context.Context) *cedar.PolicySet {
	pSet := cedar.NewPolicySet()
	for _, store := range u.stores {
		prefix := cedar.PolicyID(store.Name())
		for k, v := range store.PolicySet(ctx).Map() {
			pSet.Add(prefix+"-"+k, v)
		}
	}
	return pSet
}

func (u *unifiedStore) Name() string {
	return "UnifiedPolicyStore"
}

func NewUnifiedStore(stores ...PolicyStore) PolicyStore {
	return &unifiedStore{stores: stores}
}
