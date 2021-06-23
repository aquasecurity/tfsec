package scanner

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/result"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"
	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/metrics"

	"github.com/tfsec/tfsec/internal/app/tfsec/debug"
)

// Scanner scans HCL blocks by running all registered rules against them
type Scanner struct {
	includePassed   bool
	includeIgnored  bool
	excludedRuleIDs []string
}

// New creates a new Scanner
func New(options ...Option) *Scanner {
	s := &Scanner{}
	for _, option := range options {
		option(s)
	}
	return s
}

// Find element in list
func checkInList(id string, list []string) bool {
	codeCurrent := string(id)
	for _, codeIgnored := range list {
		if codeIgnored == codeCurrent {
			return true
		}
	}
	return false
}

func (scanner *Scanner) Scan(blocks []*block.Block) []result.Result {

	if len(blocks) == 0 {
		return nil
	}

	checkTime := metrics.Start(metrics.Check)
	defer checkTime.Stop()
	var results []result.Result
	context := hclcontext.New(blocks)
	rules := GetRegisteredRules()
	for _, checkBlock := range blocks {
		for _, r := range rules {
			func(r *rule.Rule) {
				if rule.IsRuleRequiredForBlock(r, checkBlock) {
					debug.Log("Running rule for %s on %s.%s (%s)...", r.ID, checkBlock.Type(), checkBlock.FullName(), checkBlock.Range().Filename)
					ruleResults := rule.CheckRule(r, checkBlock, context)
					if scanner.includePassed && ruleResults.All() == nil {
						res := result.New(checkBlock).WithRuleID(r.ID).WithDescription(r.Documentation.Summary).
							WithRange(checkBlock.Range()).WithStatus(result.Passed).WithSeverity(severity.None)
						results = append(results, *res)
					} else if ruleResults != nil {
						for _, ruleResult := range ruleResults.All() {
							if scanner.includeIgnored || (!scanner.checkRangeIgnored(ruleResult.RuleID, ruleResult.Range, checkBlock.Range()) && !checkInList(ruleResult.RuleID, scanner.excludedRuleIDs)) {
								results = append(results, ruleResult)
							} else {
								// rule was ignored
								metrics.Add(metrics.IgnoredChecks, 1)
								debug.Log("Ignoring '%s' based on tfsec:ignore statement", ruleResult.RuleID)
							}
						}
					}
				}
			}(&r)
		}
	}
	return results
}

func (scanner *Scanner) checkRangeIgnored(id string, r block.Range, b block.Range) bool {
	raw, err := ioutil.ReadFile(b.Filename)
	if err != nil {
		return false
	}
	ignoreAll := "tfsec:ignore:*"
	ignoreCode := fmt.Sprintf("tfsec:ignore:%s", id)
	lines := append([]string{""}, strings.Split(string(raw), "\n")...)
	startLine := r.StartLine

	// include the line above the line if available
	if r.StartLine-1 > 0 {
		startLine = r.StartLine - 1
	}

	// check the line itself
	for number := startLine; number <= r.EndLine; number++ {
		if number <= 0 || number >= len(lines) {
			continue
		}

		if strings.Contains(lines[number], ignoreAll) || strings.Contains(lines[number], ignoreCode) {
			return true
		}
	}

	// check the line above the actual resource block
	if b.StartLine-1 > 0 {
		line := lines[b.StartLine-1]
		if ignored := checkLineForIgnore(line, ignoreAll, ignoreCode); ignored {
			return true
		}
	}

	return false
}

func checkLineForIgnore(line, ignoreAll, ignoreCode string) bool {
	line = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(line, "//", ""), "#", ""))
	segments := strings.Split(line, " ")
	for _, segment := range segments {
		if segment == ignoreAll || segment == ignoreCode {
			return true
		}
	}
	return false
}
