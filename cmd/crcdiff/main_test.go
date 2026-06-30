package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestCommand runs the table of cases in testdata/cases.txt. Each case is a line
// of command-line args, a "----" separator, and the expected combined output
// (stdout, stderr, and the top-level "crcdiff: <error>" line, in program order).
// Cases are separated by blank lines; lines starting with '#' are comments.
func TestCommand(t *testing.T) {
	const path = "testdata/cases.txt"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, tc := range parseCases(t, string(data)) {
		name := tc.name
		if name == "" {
			name = "noargs"
		}
		t.Run(fmt.Sprintf("%d_%s", i, name), func(t *testing.T) {
			// A single buffer for both streams preserves the order in which the
			// command writes them; the top-level error line is appended as main
			// would print it.
			var buf bytes.Buffer
			if err := run(tc.args, &buf, &buf); err != nil {
				fmt.Fprintf(&buf, "crcdiff: %v\n", err)
			}
			if got := buf.String(); got != tc.expected {
				t.Errorf("args: %q\n--- got ----\n%s--- want ---\n%s", strings.Join(tc.args, " "), got, tc.expected)
			}
		})
	}
}

type cmdCase struct {
	name     string
	args     []string
	expected string
}

func parseCases(t *testing.T, data string) []cmdCase {
	t.Helper()
	data = strings.ReplaceAll(data, "\r\n", "\n")
	var cases []cmdCase
	for _, block := range strings.Split(data, "\n\n") {
		lines := strings.Split(strings.Trim(block, "\n"), "\n")
		// Drop leading comment and blank lines (e.g. a file or case header).
		for len(lines) > 0 && isComment(lines[0]) {
			lines = lines[1:]
		}
		if len(lines) == 0 {
			continue
		}
		sep := -1
		for i, ln := range lines {
			if ln == "----" {
				sep = i
				break
			}
		}
		if sep < 0 {
			t.Fatalf("test case missing ---- separator:\n%s", block)
		}
		var args []string
		for _, ln := range lines[:sep] {
			if isComment(ln) {
				continue
			}
			args = append(args, strings.Fields(ln)...)
		}
		expected := strings.Join(lines[sep+1:], "\n")
		if expected != "" {
			expected += "\n"
		}
		cases = append(cases, cmdCase{
			name:     strings.Join(args, "_"),
			args:     args,
			expected: expected,
		})
	}
	return cases
}

func isComment(line string) bool {
	t := strings.TrimSpace(line)
	return t == "" || strings.HasPrefix(t, "#")
}
