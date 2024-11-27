package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/awslabs/cedar-access-control-for-k8s/api/v1alpha1"
	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func DurationPtr(d time.Duration) *v1alpha1.Duration {
	dur := v1alpha1.Duration(d)
	return &dur
}

func TestConfigParse(t *testing.T) {
	cases := []struct {
		name     string
		filename string
		want     *v1alpha1.CedarConfig
		wantErr  error
	}{
		{
			name:     "json file",
			filename: "all.json",
			want: &v1alpha1.CedarConfig{
				Spec: v1alpha1.ConfigSpec{
					Stores: []v1alpha1.StoreConfig{
						{
							Type: v1alpha1.StoreTypeDirectory,
							DirectoryStore: v1alpha1.DirectoryStoreConfig{
								Path:            "/cedar/policies",
								RefreshInterval: DurationPtr(time.Minute),
							},
						},
						{
							Type: v1alpha1.StoreTypeVerifiedPermissions,
							VerifiedPermissionsStore: v1alpha1.VerifiedPermissionsStoreConfig{
								PolicyStoreID:   "F1GpuaUkZYeas3B8TBcXRj",
								RefreshInterval: DurationPtr(time.Minute * 5),
							},
						},
						{
							Type: v1alpha1.StoreTypeCRD,
						},
					},
				},
			},
		},
		{
			name:     "Yaml file",
			filename: "all.yaml",
			want: &v1alpha1.CedarConfig{
				TypeMeta: metav1.TypeMeta{
					Kind:       "StoreConfig",
					APIVersion: "cedar.k8s.aws/v1alpha1",
				},
				Spec: v1alpha1.ConfigSpec{
					Stores: []v1alpha1.StoreConfig{
						{
							Type: v1alpha1.StoreTypeDirectory,
							DirectoryStore: v1alpha1.DirectoryStoreConfig{
								Path: "/cedar/provider-policies",
							},
						},
						{
							Type: v1alpha1.StoreTypeDirectory,
							DirectoryStore: v1alpha1.DirectoryStoreConfig{
								Path:            "/cedar/k8s-policies",
								RefreshInterval: DurationPtr(time.Minute * 10),
							},
						},
						{
							Type: v1alpha1.StoreTypeVerifiedPermissions,
							VerifiedPermissionsStore: v1alpha1.VerifiedPermissionsStoreConfig{
								PolicyStoreID:   "F1GpuaUkZYeas3B8TBcXRj",
								RefreshInterval: DurationPtr(time.Minute * 5),
							},
						},
						{
							Type: v1alpha1.StoreTypeCRD,
						},
					},
				},
			},
		},
		{
			name:     "invalid store",
			filename: "invalid_type.yaml",
			want:     nil,
			wantErr:  errors.New(".spec.stores[3]: invalid store type"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fn := filepath.Join("testdata", tc.filename)
			data, err := os.ReadFile(fn)
			if err != nil {
				t.Fatal(err)
			}

			got, err := ParseConfig(data)
			if err != nil {
				if tc.wantErr != nil {
					if err.Error() != tc.wantErr.Error() {
						t.Fatalf("ParseConfig() error = %v, wantErr %v", err, tc.wantErr)
					}
					return
				}
				t.Fatal(err)
			}

			if !cmp.Equal(tc.want, got) {
				t.Errorf("ParseConfig() mismatch (-want +got):\n%s", cmp.Diff(tc.want, got))
			}
		})
	}

}
