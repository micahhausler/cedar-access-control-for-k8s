package convert

import (
	"strings"
)

func escapeDocstrings(doc string) string {
	return strings.TrimSpace(trimExampleText(doc))
}

func trimExampleText(text string) string {
	// this is mainly for Endpoints example text
	if idx := strings.Index(text, "Example:"); idx >= 0 {
		return text[0:idx]
	}
	return text
}
