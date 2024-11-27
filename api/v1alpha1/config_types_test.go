package v1alpha1_test

import (
	"errors"
	"testing"
	"time"

	"github.com/awslabs/cedar-access-control-for-k8s/api/v1alpha1"
)

func TestDurationJson(t *testing.T) {
	cases := []struct {
		name        string
		input       []byte
		skipMarshal bool
		want        v1alpha1.Duration
		wantErr     error
	}{
		{
			name:        "float64",
			input:       []byte("60000000000.0"),
			skipMarshal: true,
			want:        v1alpha1.Duration(time.Second * 60),
		},
		{
			name:  "Duration string",
			input: []byte(`"59m0s"`),
			want:  v1alpha1.Duration(time.Minute * 59),
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
			var dur v1alpha1.Duration
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

func DurationPtr(d time.Duration) *v1alpha1.Duration {
	dur := v1alpha1.Duration(d)
	return &dur
}
