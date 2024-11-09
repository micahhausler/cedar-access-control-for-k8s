package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"
)

func intOrZero(i int) int {
	if i < 0 {
		return 0
	}
	return i
}

/*
This program scans through a .cedarschema file and adjusts the tab indentation according to how
deeply nested an entity or action is under a namespace contained in curly braces `{}`.
*/
func main() {
	flag.Parse()

	content, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		panic(err)
	}

	placeholder := "__EMPTY_BRACES__"
	content = bytes.ReplaceAll(content, []byte(`{}`), []byte(placeholder))

	// replace action indentation
	content = bytes.ReplaceAll(content, []byte(`  `), []byte(``))

	content = bytes.ReplaceAll(content, []byte(`{"`), []byte(`{
"`))
	content = bytes.ReplaceAll(content, []byte(`, "`), []byte(`,
"`))
	content = bytes.ReplaceAll(content, []byte(`}`), []byte(`
}`))
	content = bytes.ReplaceAll(content, []byte(placeholder), []byte(`{}`))

	braceCount := 0
	indent := ""
	for _, line := range strings.Split(string(content), "\n") {
		indent = strings.Repeat("\t", braceCount)
		if line == "}" && braceCount == 1 {
			// handle end of namespace
			fmt.Println(line + "\n")
		} else if (strings.HasSuffix(line, "};") && !strings.HasSuffix(line, "{};")) ||
			strings.HasSuffix(line, "},") ||
			strings.HasSuffix(line, "}") &&
				!strings.HasSuffix(line, "{}") {
			// handle end of entity
			fmt.Println(strings.Repeat("\t", intOrZero(braceCount-1)) + line)
		} else if len(line) > 0 {
			// otherwise, print the non-emptty line with the appropriate indentation
			fmt.Println(indent + line)
		}
		// eat empty lines

		if strings.ContainsAny(line, "{") {
			braceCount++
		}
		if strings.ContainsAny(line, "}") {
			braceCount--
		}
	}

}
