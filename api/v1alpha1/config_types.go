package v1alpha1

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// +kubebuilder:object:root=true

// CedarConfig is a type for storing Cedar webhook configuration data
type CedarConfig struct {
	metav1.TypeMeta `json:",inline"`

	//+required
	Spec ConfigSpec `json:"spec"`
}

func (c *CedarConfig) Validate() error {
	for i, storeDef := range c.Spec.Stores {
		storeId := fmt.Sprintf(".spec.stores[%d]: ", i)
		err := storeDef.Validate()
		if err != nil {
			return errors.New(storeId + err.Error())
		}
	}
	return nil
}

type ConfigSpec struct {
	//+required
	Stores []StoreConfig `json:"stores"`
}

type StoreConfig struct {
	//+kubebuilder:validation:Enum=directory;crd;verifiedPermissions
	//+required
	Type string `json:"type"`
	//+optional
	DirectoryStore DirectoryStoreConfig `json:"directoryStore,omitempty"`
	//+optional
	CRDStore CRDStoreConfig `json:"crdStore,omitempty"`
	//+optional
	VerifiedPermissionsStore VerifiedPermissionsStoreConfig `json:"verifiedPermissionsStore,omitempty"`
}

type DirectoryStoreConfig struct {
	//+required
	Path string `json:"path"`
	//+optional
	RefreshInterval *Duration `json:"refreshInterval,omitempty"`
}

type CRDStoreConfig struct {
	//+optional
	KubeconfigContext string `json:"kubeconfigContext,omitempty"`
}

type VerifiedPermissionsStoreConfig struct {
	//+required
	PolicyStoreID string `json:"policyStoreId"`
	//+optional
	RefreshInterval *Duration `json:"refreshInterval,omitempty"`
	//+optional
	AWSRegion string `json:"awsRegion,omitempty"`
	//+optional
	AWSProfile string `json:"awsProfile,omitempty"`
}

func (c *StoreConfig) Validate() error {
	switch c.Type {
	case StoreTypeDirectory:
		if c.DirectoryStore.Path == "" {
			return errors.New("directory store path is required")
		}
		if c.DirectoryStore.RefreshInterval != nil {
			if *c.DirectoryStore.RefreshInterval < Duration(time.Second*30) {
				return errors.New("directory store refresh interval must be at least 30s")
			}
			if *c.DirectoryStore.RefreshInterval > Duration(time.Hour*24*7) {
				return errors.New("directory store refresh interval must be under 1 week (168h)")
			}
		} else {
			defaultDur := Duration(time.Minute * 1)
			c.DirectoryStore.RefreshInterval = &defaultDur
		}
	case StoreTypeCRD:
		// no-op
	case StoreTypeVerifiedPermissions:
		if c.VerifiedPermissionsStore.PolicyStoreID == "" {
			return errors.New("verified permissions store policy store id is required")
		}
		if c.VerifiedPermissionsStore.RefreshInterval != nil {
			if *c.VerifiedPermissionsStore.RefreshInterval < Duration(time.Second*30) {
				return errors.New("verified permissions refresh interval must be at least 30s")
			}
			if *c.VerifiedPermissionsStore.RefreshInterval > Duration(time.Hour*24*7) {
				return errors.New("verified permissions refresh interval must be under 1 week (168h)")
			}
		} else {
			defaultDur := Duration(time.Minute * 5)
			c.VerifiedPermissionsStore.RefreshInterval = &defaultDur
		}

	default:
		return errors.New("invalid store type")
	}
	return nil
}
