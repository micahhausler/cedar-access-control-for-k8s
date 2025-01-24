package convert

import (
	"testing"
)

func TestEscapeDocstring(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			"No example",
			"Some text",
			"Some text",
		},
		{
			"Example at the end",
			"Some text\nExample: some example",
			"Some text",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := escapeDocstrings(tc.input)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}

}
