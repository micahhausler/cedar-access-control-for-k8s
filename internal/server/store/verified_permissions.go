package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	avp "github.com/aws/aws-sdk-go-v2/service/verifiedpermissions"
	avptypes "github.com/aws/aws-sdk-go-v2/service/verifiedpermissions/types"
	"github.com/cedar-policy/cedar-go"
	"k8s.io/klog/v2"
)

type VerifiedPermissionStore struct {
	client *avp.Client

	policyStoreID   string
	refreshInterval time.Duration

	policies   *cedar.PolicySet
	policiesMu sync.RWMutex
}

func NewVerifiedPermissionStore(cfg aws.Config, policyStoreID string, refreshInterval time.Duration) (PolicyStore, error) {
	resp := &VerifiedPermissionStore{
		client:          avp.NewFromConfig(cfg),
		policyStoreID:   policyStoreID,
		refreshInterval: refreshInterval,
	}
	resp.loadPolicies()
	go resp.reloadAsync()
	return resp, nil
}

func (s *VerifiedPermissionStore) InitalPolicyLoadComplete() bool {
	return true
}

func (s *VerifiedPermissionStore) Name() string {
	return fmt.Sprintf("VerifiedPermissionStore-%s", s.policyStoreID)
}

func (s *VerifiedPermissionStore) PolicySet() *cedar.PolicySet {
	s.policiesMu.RLock()
	defer s.policiesMu.RUnlock()
	return s.policies
}

func (s *VerifiedPermissionStore) reloadAsync() {
	ticker := time.NewTicker(s.refreshInterval)
	for range ticker.C {
		s.loadPolicies()
	}
}

func (s *VerifiedPermissionStore) loadPolicies() {
	paginator := avp.NewListPoliciesPaginator(s.client, &avp.ListPoliciesInput{
		PolicyStoreId: aws.String(s.policyStoreID),
		Filter: &avptypes.PolicyFilter{
			PolicyType: avptypes.PolicyTypeStatic,
		},
	})

	s.policiesMu.Lock()
	defer s.policiesMu.Unlock()
	ctx := context.Background()

	pSet := cedar.NewPolicySet()
	for paginator.HasMorePages() {
		policies, err := paginator.NextPage(ctx)
		if err != nil {
			klog.ErrorS(err, "failed to load AVP policies", "policyStoreId", s.policyStoreID)
			return
		}
		for _, p := range policies.Policies {
			policy, err := s.client.GetPolicy(ctx, &avp.GetPolicyInput{
				PolicyId:      p.PolicyId,
				PolicyStoreId: aws.String(s.policyStoreID),
			})
			if err != nil {
				klog.ErrorS(err, "failed to fetch AVP policy", "policyId", *p.PolicyId, "policyStoreId", s.policyStoreID)
				continue
			}
			staticPolicy := policy.Definition.(*avptypes.PolicyDefinitionDetailMemberStatic)
			statement := staticPolicy.Value.Statement

			pList, err := cedar.NewPolicyListFromBytes(*p.PolicyId, []byte(*statement))
			if err != nil {
				klog.ErrorS(err, "failed to parse Cedar policy", "policyId", *p.PolicyId, "policyStoreId", s.policyStoreID)
				continue
			}
			for i, policyStatement := range pList {
				pSet.Add(cedar.PolicyID(fmt.Sprintf("%s.%d", *p.PolicyId, i)), policyStatement)
			}
		}
	}
	s.policies = pSet
}
