package scanner

import (
	"sort"

	"github.com/aquasecurity/tfsec/pkg/defsec/infra"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/metrics"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
)

// Scanner scans HCL blocks by running all registered rules against them
type Scanner struct {
	includePassed     bool
	includeIgnored    bool
	excludedRuleIDs   []string
	ignoreCheckErrors bool
	workspaceName     string
	infra             *infra.Context
}

// New creates a new Scanner
func New(options ...Option) *Scanner {
	s := &Scanner{
		ignoreCheckErrors: true,
	}
	for _, option := range options {
		option(s)
	}
	return s
}

// Find element in list
func checkInList(id string, legacyID string, list []string) bool {
	for _, codeIgnored := range list {
		if codeIgnored == id || (legacyID != "" && codeIgnored == legacyID) {
			return true
		}
	}
	return false
}

func (scanner *Scanner) Scan() []result.Result {
	checkTime := metrics.Start(metrics.Check)
	defer checkTime.Stop()
	results := scanner.scanAll()
	sort.Slice(results, func(i, j int) bool {
		switch {
		case results[i].RuleID < results[j].RuleID:
			return true
		case results[i].RuleID > results[j].RuleID:
			return false
		default:
			return results[i].HashCode() > results[j].HashCode()
		}
	})
	return results
}

func (scanner *Scanner) scanAll() []result.Result {
	var results []result.Result
	rules := GetRegisteredRules()
	for _, r := range rules {
		ruleResults := rule.CheckRule(&r, scanner.infra, scanner.ignoreCheckErrors)
		if ruleResults != nil {
			for _, ruleResult := range ruleResults.All() {
				if ruleResult.Severity == severity.None {
					ruleResult.Severity = r.DefaultSeverity
				}
				if !scanner.includeIgnored && (ruleResult.IsIgnored(scanner.workspaceName) || checkInList(ruleResult.RuleID, ruleResult.LegacyRuleID, scanner.excludedRuleIDs)) {
					// rule was ignored
					metrics.Add(metrics.IgnoredChecks, 1)
					debug.Log("Ignoring '%s'", ruleResult.RuleID)
				} else {
					results = append(results, *ruleResult)
				}
			}
		}
	}
	return results
}
