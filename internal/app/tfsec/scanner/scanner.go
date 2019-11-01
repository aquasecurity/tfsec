package scanner

import (
	"io/ioutil"
	"strings"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

// Scanner scans HCL blocks by running all registered checks against them
type Scanner struct {
}

// New creates a new Scanner
func New() *Scanner {
	return &Scanner{}
}

// Scan takes all available hcl blocks and an optional context, and returns a slice of results. Each result indicates a potential security problem.
func (scanner *Scanner) Scan(blocks []*parser.Block) []checks.Result {
	var results []checks.Result
	for _, block := range blocks {
		for _, check := range checks.GetRegisteredChecks() {
			if check.IsRequiredForBlock(block) {
				for _, result := range check.Run(block) {
					if !scanner.checkRangeIgnored(result.Range) {
						results = append(results, result)
					}
				}
			}
		}
	}
	return results
}

func (scanner *Scanner) checkRangeIgnored(r parser.Range) bool {
	raw, err := ioutil.ReadFile(r.Filename)
	if err != nil {
		return false
	}
	lines := append([]string{""}, strings.Split(string(raw), "\n")...)
	for number := r.StartLine; number <= r.EndLine; number++ {
		if number <= 0 || number >= len(lines) {
			continue
		}
		if strings.Contains(lines[number], "tfsec:ignore") {
			return true
		}
	}

	if r.StartLine-1 > 0 {
		line := lines[r.StartLine-1]
		line = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(line, "//", ""), "#", ""))
		if line == "tfsec:ignore" {
			return true
		}
	}

	return false
}
