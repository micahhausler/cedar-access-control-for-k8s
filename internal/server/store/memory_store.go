package store

import (
	"context"

	"github.com/cedar-policy/cedar-go"
)

type memoryStore struct {
	policies     *cedar.PolicySet
	loadComplete bool
}

// NewMemoryStore returns an in-memory PolicyStore that is immutable and always ready.
//
// This policy store is just a holder for a *cedar.PolicySet by wrapping
// `cedar.NewPolicySetFromBytes()`
func NewMemoryStore(filename string, document []byte, loadComplete bool) (PolicyStore, error) {
	policies, err := cedar.NewPolicySetFromBytes(filename, document)
	if err != nil {
		return nil, err
	}
	return &memoryStore{
		policies:     policies,
		loadComplete: loadComplete,
	}, nil
}

func (s *memoryStore) PolicySet(_ context.Context) *cedar.PolicySet {
	return s.policies
}

func (s *memoryStore) InitalPolicyLoadComplete() bool {
	return s.loadComplete
}
