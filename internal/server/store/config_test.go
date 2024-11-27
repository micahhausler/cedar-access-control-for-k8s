package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDurationJson(t *testing.T) {
	cases := []struct {
		name        string
		input       []byte
		skipMarshal bool
		want        Duration
		wantErr     error
	}{
		{
			name:        "float64",
			input:       []byte("60000000000.0"),
			skipMarshal: true,
			want:        Duration(time.Second * 60),
		},
		{
			name:  "Duration string",
			input: []byte(`"59m0s"`),
			want:  Duration(time.Minute * 59),
		},
		{
			name:    "invalid string",
			input:   []byte(`"60x"`),
			wantErr: errors.New(`time: unknown unit "x" in duration "60x"`),
		},
		{
			name:    "invalid type",
			input:   []byte(`true`),
			wantErr: errors.New("invalid duration"),
		},
		{
			name:    "invalid json",
			input:   []byte(`{true}`),
			wantErr: errors.New("invalid character 't' looking for beginning of object key string"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var dur Duration
			err := dur.UnmarshalJSON(tc.input)
			if err != nil {
				if tc.wantErr != nil {
					if err.Error() != tc.wantErr.Error() {
						t.Fatalf("UnmarshalJSON() error = '%v', wantErr '%v'", err, tc.wantErr)
					}
					return
				}
				t.Fatal(err)
			}
			if dur != tc.want {
				t.Fatalf("got %v, want %v", dur, tc.want)
			}

			if !tc.skipMarshal {
				got, err := dur.MarshalJSON()
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != string(tc.input) {
					t.Errorf("MarshalJSON() = %v, want %v", string(got), string(tc.input))
				}
			}
		})
	}
}

func DurationPtr(d time.Duration) *Duration {
	dur := Duration(d)
	return &dur
}

func TestConfigParse(t *testing.T) {

	cases := []struct {
		name     string
		filename string
		want     *Config
		wantErr  error
	}{
		{
			name:     "json file",
			filename: "all.json",
			want: &Config{
				Spec: ConfigSpec{
					Stores: []StoreConfig{
						{
							Type: StoreTypeDirectory,
							DirectoryStore: DirectoryStoreConfig{
								Path:            "/cedar/policies",
								RefreshInterval: DurationPtr(time.Minute),
							},
						},
						{
							Type: StoreTypeVerifiedPermissions,
							VerifiedPermissionsStore: VerifiedPermissionsStoreConfig{
								PolicyStoreID:   "F1GpuaUkZYeas3B8TBcXRj",
								RefreshInterval: DurationPtr(time.Minute * 5),
							},
						},
						{
							Type: StoreTypeCRD,
						},
					},
				},
			},
		},
		{
			name:     "Yaml file",
			filename: "all.yaml",
			want: &Config{
				TypeMeta: metav1.TypeMeta{
					Kind:       "StoreConfig",
					APIVersion: "cedar.k8s.aws/v1alpha1",
				},
				Spec: ConfigSpec{
					Stores: []StoreConfig{
						{
							Type: StoreTypeDirectory,
							DirectoryStore: DirectoryStoreConfig{
								Path:            "/cedar/provider-policies",
								RefreshInterval: DurationPtr(time.Minute),
							},
						},
						{
							Type: StoreTypeDirectory,
							DirectoryStore: DirectoryStoreConfig{
								Path:            "/cedar/k8s-policies",
								RefreshInterval: DurationPtr(time.Minute * 10),
							},
						},
						{
							Type: StoreTypeVerifiedPermissions,
							VerifiedPermissionsStore: VerifiedPermissionsStoreConfig{
								PolicyStoreID:   "F1GpuaUkZYeas3B8TBcXRj",
								RefreshInterval: DurationPtr(time.Minute * 5),
							},
						},
						{
							Type: StoreTypeCRD,
						},
					},
				},
			},
		},
		{
			name:     "invalid store",
			filename: "invalid_type.yaml",
			want:     nil,
			wantErr:  errors.New("invalid store type"),
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
