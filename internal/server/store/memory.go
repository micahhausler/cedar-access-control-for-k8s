package store

import (
	"github.com/cedar-policy/cedar-go"
)

type memoryStore struct {
	policies     *cedar.PolicySet
	loadComplete bool
	name         string
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
		name:         filename,
	}, nil
}

func (s *memoryStore) PolicySet() *cedar.PolicySet {
	return s.policies
}

func (s *memoryStore) InitalPolicyLoadComplete() bool {
	return s.loadComplete
}

func (s *memoryStore) Name() string {
	return s.name
}

// StaticStore is a store type around a cedar.PolicySet
type StaticStore cedar.PolicySet

// PolicySet returns a pointer to the underlying cedar.PolicySet
func (s StaticStore) PolicySet() *cedar.PolicySet {
	ps := cedar.PolicySet(s)
	return &ps
}

// Name returns the name "StaticStore"
func (s StaticStore) Name() string { return "StaticStore" }

// InitialPolicyLoadComplete returns true
func (s StaticStore) InitalPolicyLoadComplete() bool { return true }
