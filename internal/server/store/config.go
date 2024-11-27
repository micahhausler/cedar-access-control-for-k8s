package store

import (
	"context"
	"encoding/json"
	"fmt"

	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

const (
	StoreTypeDirectory           = "directory"
	StoreTypeCRD                 = "crd"
	StoreTypeVerifiedPermissions = "verifiedPermissions"
)

type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		*d = Duration(time.Duration(value))
		return nil
	case string:
		tmp, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*d = Duration(tmp)
		return nil
	default:
		return errors.New("invalid duration")
	}
}

type Config struct {
	metav1.TypeMeta `json:",inline"`

	Spec ConfigSpec `json:"spec"`
}

type ConfigSpec struct {
	Stores []StoreConfig `json:"stores"`
}

type StoreConfig struct {
	Type                     string                         `json:"type"`
	DirectoryStore           DirectoryStoreConfig           `json:"directoryStore"`
	CRDStore                 CRDStoreConfig                 `json:"crdStore"`
	VerifiedPermissionsStore VerifiedPermissionsStoreConfig `json:"verifiedPermissionsStore"`
}

type DirectoryStoreConfig struct {
	Path            string    `json:"path"`
	RefreshInterval *Duration `json:"refreshInterval,omitempty"`
}

type CRDStoreConfig struct {
	KubeconfigContext string `json:"kubeconfigContext,omitempty"`
}

type VerifiedPermissionsStoreConfig struct {
	PolicyStoreID   string    `json:"policyStoreId"`
	RefreshInterval *Duration `json:"refreshInterval,omitempty"`
	AWSRegion       string    `json:"awsRegion,omitempty"`
	AWSProfile      string    `json:"awsProfile,omitempty"`
}

func ParseConfig(in []byte) (*Config, error) {
	config := &Config{}
	err := yaml.Unmarshal(in, config)
	if err != nil {
		return nil, err
	}

	return config, config.validate()
}

func (c *Config) validate() error {
	for i, storeDef := range c.Spec.Stores {
		storeId := fmt.Sprintf("stores[%d]: ", i)
		switch storeDef.Type {
		case StoreTypeDirectory:
			if storeDef.DirectoryStore.Path == "" {
				return errors.New(storeId + "directory store path is required")
			}
			if storeDef.DirectoryStore.RefreshInterval != nil {
				if *storeDef.DirectoryStore.RefreshInterval < Duration(time.Second*30) {
					return errors.New(storeId + "directory store refresh interval must be at least 30s")
				}
				if *storeDef.DirectoryStore.RefreshInterval > Duration(time.Hour*24*7) {
					return errors.New(storeId + "directory store refresh interval must be under 1 week (168h)")
				}
			} else {
				defaultDur := Duration(time.Minute * 1)
				c.Spec.Stores[i].DirectoryStore.RefreshInterval = &defaultDur
			}
		case StoreTypeCRD:
			// no-op
		case StoreTypeVerifiedPermissions:
			if storeDef.VerifiedPermissionsStore.PolicyStoreID == "" {
				return errors.New(storeId + "verified permissions store policy store id is required")
			}
			if storeDef.VerifiedPermissionsStore.RefreshInterval != nil {
				if *storeDef.VerifiedPermissionsStore.RefreshInterval < Duration(time.Second*30) {
					return errors.New(storeId + "verified permissions refresh interval must be at least 30s")
				}
				if *storeDef.VerifiedPermissionsStore.RefreshInterval > Duration(time.Hour*24*7) {
					return errors.New(storeId + "verified permissions refresh interval must be under 1 week (168h)")
				}
			} else {
				defaultDur := Duration(time.Minute * 5)
				c.Spec.Stores[i].VerifiedPermissionsStore.RefreshInterval = &defaultDur
			}

		default:
			return errors.New("invalid store type")
		}
	}
	return nil
}

func (c *Config) TieredPolicyStores() (TieredPolicyStores, error) {
	var stores []PolicyStore
	for _, storeDef := range c.Spec.Stores {
		switch storeDef.Type {
		case StoreTypeDirectory:
			stores = append(stores, NewDirectoryPolicyStore(
				storeDef.DirectoryStore.Path,
				time.Duration(*storeDef.DirectoryStore.RefreshInterval),
			))
		case StoreTypeCRD:
			ps, err := NewCRDPolicyStore(storeDef.CRDStore.KubeconfigContext)
			if err != nil {
				return nil, err
			}
			stores = append(stores, ps)
		case StoreTypeVerifiedPermissions:
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
