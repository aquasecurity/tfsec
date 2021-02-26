package scanner

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/metrics"
	"io/ioutil"
	"strings"



	"github.com/tfsec/tfsec/internal/app/tfsec/debug"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// Scanner scans HCL blocks by running all registered checks against them
type Scanner struct {
}

type ScannerOption int

const (
	IncludePassed ScannerOption = iota
)

// New creates a new Scanner
func New() *Scanner {
	return &Scanner{}
}

// Find element in list
func checkInList(code RuleCode, list []string) bool {
	codeCurrent := fmt.Sprintf("%s", code)
	for _, codeIgnored := range list {
		if codeIgnored == codeCurrent {
			return true
		}
	}
	return false
}

func (scanner *Scanner) Scan(blocks []*parser.Block, excludedChecksList []string, options ...ScannerOption) []Result {

	includePassed := false

	for _, option := range options {
		if option == IncludePassed {
			includePassed = true
		}
	}

	if len(blocks) == 0 {
		return nil
	}

	checkTime := metrics.Start(metrics.Check)
	defer checkTime.Stop()
	var results []Result
	context := &Context{blocks: blocks}
	checks := GetRegisteredChecks()
	for _, block := range blocks {
		for _, check := range checks {
			func(check Check) {
				if check.IsRequiredForBlock(block) {
					debug.Log("Running check for %s on %s.%s (%s)...", check.Code, block.Type(), block.FullName(), block.Range().Filename)
					var res = check.Run(block, context)
					if includePassed && res == nil {
						results = append(results, check.NewPassingResult(block.Range()))
					} else {
						for _, result := range res {
							if !scanner.checkRangeIgnored(result.RuleID, result.Range) && !checkInList(result.RuleID, excludedChecksList) {
								results = append(results, result)
							}
						}
					}
				}
			}(check)
		}
	}
	return results
}

func (scanner *Scanner) checkRangeIgnored(code RuleCode, r parser.Range) bool {
	raw, err := ioutil.ReadFile(r.Filename)
	if err != nil {
		return false
	}
	ignoreAll := "tfsec:ignore:*"
	ignoreCode := fmt.Sprintf("tfsec:ignore:%s", code)
	lines := append([]string{""}, strings.Split(string(raw), "\n")...)
	for number := r.StartLine; number <= r.EndLine; number++ {
		if number <= 0 || number >= len(lines) {
			continue
		}
		if strings.Contains(lines[number], ignoreAll) || strings.Contains(lines[number], ignoreCode) {
			return true
		}
	}

	if r.StartLine-1 > 0 {
		line := lines[r.StartLine-1]
		line = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(line, "//", ""), "#", ""))
		segments := strings.Split(line, " ")
		for _, segment := range segments {
			if segment == ignoreAll || segment == ignoreCode {
				return true
			}
		}

	}

	return false
}
