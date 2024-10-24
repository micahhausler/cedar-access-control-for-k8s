package store

import (
	"context"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	cedarv1alpha1 "github.com/awslabs/cedar-access-control-for-k8s/api/v1alpha1"
	"github.com/cedar-policy/cedar-go"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type crdPolicyStore struct {
	initalPolicyLoadComplete   bool
	initalPolicyLoadCompleteMu sync.RWMutex

	cache cache.Cache
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
	set := cedar.NewPolicySet()
	policies := &cedarv1alpha1.PolicyList{}

	// TODO: Super naive, reads all policies from cache every time
	// TODO: support paginated results
	err := s.cache.List(ctx, policies, &client.ListOptions{})
	if err != nil {
		klog.Errorf("Error listing policies: %v", err)
		return set
	}
	for _, obj := range policies.Items {

		pList, err := cedar.NewPolicyListFromBytes(obj.Name, []byte(obj.Spec.Content))
		if err != nil {
			klog.ErrorS(err, "Error parsing policy", "policy", obj.Name)
			continue
		}
		for i, policy := range pList {
			set.Store(cedar.PolicyID(obj.Name+strconv.Itoa(i)), policy)
		}
	}

	return set
}

func (s *crdPolicyStore) Name() string {
	return "CRDPolicyStore"
}

func NewCRDPolicyStore() (PolicyStore, error) {
	resp := &crdPolicyStore{
		initalPolicyLoadComplete: false,
	}
	go resp.populatePolicies()
	return resp, nil
}
