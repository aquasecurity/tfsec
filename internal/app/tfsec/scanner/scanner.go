package scanner

import (
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
	includePassed     bool
	includeIgnored    bool
	excludedRuleIDs   []string
	ignoreCheckErrors bool
	workspaceName     string
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
		if codeIgnored == id || codeIgnored == legacyID {
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
					debug.Log("Running rule for %s on %s (%s)...", r.ID(), checkBlock.Reference(), checkBlock.Range().Filename)
					ruleResults := rule.CheckRule(r, checkBlock, context, scanner.ignoreCheckErrors)
					if scanner.includePassed && ruleResults.All() == nil {
						res := result.New(checkBlock).
							WithLegacyRuleID(r.LegacyID).
							WithRuleID(r.ID()).
							WithDescription("Resource '%s' passed check: %s", checkBlock.FullName(), r.Documentation.Summary).
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
			}(&r)
		}
	}
	return results
}
