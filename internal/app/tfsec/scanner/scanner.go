package scanner

import (
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/metrics"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
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

func (scanner *Scanner) Scan(blocks []block.Block) []result.Result {

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
						res := result.New(checkBlock).
							WithRuleID(r.ID).
							WithDescription(fmt.Sprintf("Resource '%s' passed check: %s", checkBlock.FullName(), r.Documentation.Summary)).
							WithRange(checkBlock.Range()).
							WithStatus(result.Passed).
							WithImpact(r.Documentation.Impact).
							WithResolution(r.Documentation.Resolution).
							WithSeverity(r.DefaultSeverity)
						results = append(results, *res)
					} else if ruleResults != nil {
						for _, ruleResult := range ruleResults.All() {
							if ruleResult.Severity == severity.None {
								ruleResult.Severity = r.DefaultSeverity
							}
							if scanner.includeIgnored || (!scanner.checkRangeIgnored(ruleResult.RuleID, ruleResult.Range, checkBlock) && !checkInList(ruleResult.RuleID, scanner.excludedRuleIDs)) {
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

func readLines(filename string) ([]string, error) {
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return append([]string{""}, strings.Split(string(raw), "\n")...), nil
}

func (scanner *Scanner) checkRangeIgnored(id string, r block.Range, b block.Block) bool {
	lines, err := readLines(b.Range().Filename)
	if err != nil {
		debug.Log("the file containing the block could not be opened. %s", err.Error())
	}
	startLine := r.StartLine

	ignoreAll := "tfsec:ignore:*"
	ignoreCode := fmt.Sprintf("tfsec:ignore:%s", id)

	var foundValidIgnore bool
	var ignoreLine string

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
			foundValidIgnore = true
			ignoreLine = lines[number]
			break
		}
	}

	// check the line above the actual resource block
	if b.Range().StartLine-1 > 0 {
		line := lines[b.Range().StartLine-1]
		if strings.Contains(line, ignoreAll) || strings.Contains(line, ignoreCode) {
			foundValidIgnore = true
			ignoreLine = line
		}
	}

	// if nothing found yet, walk up any module references
	if !foundValidIgnore {
		foundValidIgnore, ignoreLine = traverseModuleTree(b, ignoreAll, ignoreCode)
	}

	if foundValidIgnore {
		return isIgnoreWithinExpiry(ignoreLine, id, b.Range())
	}

	return foundValidIgnore
}

func isIgnoreWithinExpiry(ignoreLine string, id string, r block.Range) bool {
	expWithCode := fmt.Sprintf("%s:exp:", id)
	if indexExpFound := strings.Index(ignoreLine, expWithCode); indexExpFound > 0 {
		debug.Log("Expiration date found on ignore '%s'", ignoreLine)
		layout := fmt.Sprintf("%s2006-01-02", expWithCode)
		expDate := ignoreLine[indexExpFound : indexExpFound+len(layout)]
		parsedDate, err := time.Parse(layout, expDate)
		if err != nil {
			// if we can't parse the date then we don't want to ignore the range
			debug.Log("Unable to parse exp date in ignore: '%s'. The date format is invalid. Supported format 'exp:yyyy-mm-dd'.", ignoreLine)
			return false
		}
		currentTime := time.Now()
		ignoreExpirationDateBreached := currentTime.After(parsedDate)
		if ignoreExpirationDateBreached {
			debug.Log("Ignore expired, check will be performed Filename: %s:%d", r.Filename, r.StartLine)
		}
		return !ignoreExpirationDateBreached
	}

	return true
}

func traverseModuleTree(b block.Block, ignoreAll, ignoreCode string) (bool, string) {

	// check on the module
	if b.HasModuleBlock() {
		moduleBlock, err := b.GetModuleBlock()
		if err != nil {
			debug.Log("error occurred trying to get the module block for [%s]. %s", b.FullName(), err.Error())
			return false, ""
		}
		moduleLines, err := readLines(moduleBlock.Range().Filename)
		if err != nil {
			return false, ""
		}
		if moduleBlock.Range().StartLine-1 > 0 {
			line := moduleLines[moduleBlock.Range().StartLine-1]
			if strings.Contains(line, ignoreAll) || strings.Contains(line, ignoreCode) {
				return true, line
			}
		}

		return traverseModuleTree(moduleBlock, ignoreAll, ignoreCode)
	}

	return false, ""
}
