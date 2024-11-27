package store

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/awslabs/cedar-access-control-for-k8s/api/v1alpha1"
	"sigs.k8s.io/yaml"
)

func ParseConfig(in []byte) (*v1alpha1.CedarConfig, error) {
	config := &v1alpha1.CedarConfig{}
	err := yaml.Unmarshal(in, config)
	if err != nil {
		return nil, err
	}
	return config, config.Validate()
}

func CedarConfigStores(c *v1alpha1.CedarConfig) (TieredPolicyStores, error) {
	if c == nil {
		return nil, nil
	}
	var stores []PolicyStore
	for _, storeDef := range c.Spec.Stores {
		switch storeDef.Type {
		case v1alpha1.StoreTypeDirectory:
			stores = append(stores, NewDirectoryPolicyStore(
				storeDef.DirectoryStore.Path,
				time.Duration(*storeDef.DirectoryStore.RefreshInterval),
			))
		case v1alpha1.StoreTypeCRD:
			ps, err := NewCRDPolicyStore(storeDef.CRDStore.KubeconfigContext)
			if err != nil {
				return nil, err
			}
			stores = append(stores, ps)
		case v1alpha1.StoreTypeVerifiedPermissions:
			loadFuncs := []func(*config.LoadOptions) error{}
			if storeDef.VerifiedPermissionsStore.AWSRegion != "" {
				loadFuncs = append(loadFuncs, config.WithRegion(storeDef.VerifiedPermissionsStore.AWSRegion))
			}
			if storeDef.VerifiedPermissionsStore.AWSProfile != "" {
				loadFuncs = append(loadFuncs, config.WithSharedConfigProfile(storeDef.VerifiedPermissionsStore.AWSProfile))
			}
			cfg, err := config.LoadDefaultConfig(context.Background(), loadFuncs...)
			if err != nil {
				return nil, err
			}

			ps, err := NewVerifiedPermissionStore(
				cfg,
				storeDef.VerifiedPermissionsStore.PolicyStoreID,
				time.Duration(*storeDef.VerifiedPermissionsStore.RefreshInterval),
			)
			if err != nil {
				return nil, err
			}
			stores = append(stores, ps)
		}
	}
	return stores, nil
}
