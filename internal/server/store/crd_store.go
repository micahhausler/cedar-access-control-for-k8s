package store

import (
	"context"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/awslabs/cedar-access-control-for-k8s/api/v1alpha1"
	"github.com/cedar-policy/cedar-go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"sigs.k8s.io/controller-runtime/pkg/cache"
)

type crdPolicyStore struct {
	initalPolicyLoadComplete   bool
	initalPolicyLoadCompleteMu sync.RWMutex

	cache cache.Cache

	// a map of resource name to policyID names
	policyNames map[string][]cedar.PolicyID
	policies    *cedar.PolicySet
	policiesMu  sync.RWMutex
}

func (s *crdPolicyStore) OnAdd(rawObj interface{}, isInInitialList bool) {
	obj := rawObj.(*v1alpha1.Policy)

	s.policiesMu.Lock()
	defer s.policiesMu.Unlock()

	pList, err := cedar.NewPolicyListFromBytes(obj.Name, []byte(obj.Spec.Content))
	if err != nil {
		klog.ErrorS(err, "Error parsing policy", "policy", obj.Name)
		return
	}

	policyNames := []cedar.PolicyID{}
	for i, policy := range pList {
		// Use UID for uniqeness to avoid naming collisions (ex: the 0th policy from "mypolicy1" could conflict with the 11th policy from "mypolicy")
		pname := cedar.PolicyID(obj.Name + strconv.Itoa(i) + "-" + string(obj.UID))
		policyNames = append(policyNames, pname)
		s.policies.Add(pname, policy)
	}
	s.policyNames[obj.Name] = policyNames
}

func (s *crdPolicyStore) OnUpdate(rawOldObj, rawNewObj interface{}) {
	oldObj, ok := rawOldObj.(*v1alpha1.Policy)
	if !ok {
		klog.Error("Error updating old policy obj to Policy")
		return
	}
	newObj, ok := rawNewObj.(*v1alpha1.Policy)
	if !ok {
		klog.Error("Error updating new policy obj to Policy")
		return
	}

	s.policiesMu.Lock()
	defer s.policiesMu.Unlock()

	// clear out old policies from the map, if it exists
	if policyNames, ok := s.policyNames[oldObj.Name]; ok {
		for _, name := range policyNames {
			s.policies.Remove(name)
		}
		delete(s.policyNames, oldObj.Name)
	}

	// add the updated policy
	pList, err := cedar.NewPolicyListFromBytes(newObj.Name, []byte(newObj.Spec.Content))
	if err != nil {
		klog.ErrorS(err, "Error parsing updated policy", "policy", newObj.Name)
		return
	}
	policyNames := []cedar.PolicyID{}
	for i, policy := range pList {
		// Use UID for uniqeness to avoid naming collisions
		// ex: the 0th policy from "mypolicy1" could conflict with the 11th policy from "mypolicy")
		pname := cedar.PolicyID(newObj.Name + strconv.Itoa(i) + "-" + string(newObj.UID))
		policyNames = append(policyNames, pname)
		s.policies.Add(pname, policy)
	}
	s.policyNames[newObj.Name] = policyNames
}

func (s *crdPolicyStore) OnDelete(rawObj interface{}) {
	obj := rawObj.(*v1alpha1.Policy)
	s.policiesMu.Lock()
	defer s.policiesMu.Unlock()
	// clear out old policies from the policySet, if it exists
	if policyNames, ok := s.policyNames[obj.Name]; ok {
		for _, name := range policyNames {
			s.policies.Remove(name)
		}
		delete(s.policyNames, obj.Name)
	}
}

func (s *crdPolicyStore) InitalPolicyLoadComplete() bool {
	s.initalPolicyLoadCompleteMu.RLock()
	defer s.initalPolicyLoadCompleteMu.RUnlock()
	return s.initalPolicyLoadComplete
}

func (s *crdPolicyStore) populatePolicies() {
	var config *rest.Config
	var err error

	// TODO: plumb down kubeconfig via flags
	if kubeconfigPath, ok := os.LookupEnv("KUBECONFIG"); ok {
		for {
			fi, err := fs.Stat(os.DirFS("/"), strings.TrimLeft(kubeconfigPath, "/"))
			if err == nil {
				klog.Infof("kubeconfig found at %s", kubeconfigPath)
				if fi.Size() == 0 {
					klog.Infof("kubeconfig is empty, waiting 5s for it to be populated")
				} else {
					break
				}
			} else {
				klog.Infof("kubeconfig not yet found at '%s', waiting 5s for it to be created: %v", kubeconfigPath, err)
			}
			time.Sleep(5 * time.Second)
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			klog.Fatalf("Error building kubeconfig: %v", err)
			return
		}
	} else {
		klog.Infof("No kubeconfig found, using in-cluster config")
		config, err = rest.InClusterConfig()
		if err != nil {
			klog.Fatalf("Error building in-cluster config: %v", err)
			return
		}
	}

	c, err := cache.New(config, cache.Options{
		Scheme: scheme,
	})
	if err != nil {
		klog.Fatalf("Error creating cache: %v", err)
		return
	}

	policy := v1alpha1.Policy{TypeMeta: metav1.TypeMeta{Kind: "Policy", APIVersion: v1alpha1.GroupVersion.String()}}
	policyInformer, err := c.GetInformer(context.Background(), &policy)
	if err != nil {
		klog.Fatalf("Error getting cedar policy informer")
	}
	_, err = policyInformer.AddEventHandler(s)
	if err != nil {
		klog.Fatalf("Error adding policy store event handler")
	}

	go func() {
		err := c.Start(context.Background())
		if err != nil {
			klog.Fatalf("Error starting cache: %v", err)
			return
		}
	}()
	s.initalPolicyLoadCompleteMu.Lock()
	s.cache = c
	s.initalPolicyLoadComplete = true
	s.initalPolicyLoadCompleteMu.Unlock()
	klog.Infof("Cache started")
}

func (s *crdPolicyStore) PolicySet(ctx context.Context) *cedar.PolicySet {
	s.policiesMu.RLock()
	defer s.policiesMu.RUnlock()
	return s.policies
}

func (s *crdPolicyStore) Name() string {
	return "CRDPolicyStore"
}

func NewCRDPolicyStore() (PolicyStore, error) {
	resp := &crdPolicyStore{
		initalPolicyLoadComplete: false,
		policyNames:              map[string][]cedar.PolicyID{},
		policies:                 cedar.NewPolicySet(),
	}
	go resp.populatePolicies()
	return resp, nil
}
