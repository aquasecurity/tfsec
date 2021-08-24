package scanner

import (
	"sort"

	"github.com/aquasecurity/defsec/result"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/adapter"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/metrics"
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
		if codeIgnored == id || (legacyID != "" && codeIgnored == legacyID) {
			return true
		}
	}
	return false
}

func (scanner *Scanner) Scan(modules []block.Module) []*result.Result {

	adaptationTime := metrics.Start(metrics.Adaptation)
	infra := adapter.Adapt(modules)
	adaptationTime.Stop()

	var results []*result.Result

	// run defsec checks
	infraCheckTime := metrics.Start(metrics.InfraChecks)
	for _, r := range GetRegisteredRules() {
		func() {
			if scanner.ignoreCheckErrors {
				defer r.RecoverFromCheckPanic()
			}
			infraResults := r.CheckAgainstContext(infra)
			results = append(results, infraResults.All()...)
		}()
	}
	infraCheckTime.Stop()

	// run internal checks
	hclCheckTime := metrics.Start(metrics.HCLChecks)
	for _, module := range modules {
		for _, b := range module.GetBlocks() {
			for _, r := range GetRegisteredRules() {
				func() {
					if scanner.ignoreCheckErrors {
						defer r.RecoverFromCheckPanic()
					}
					internalResults := r.CheckAgainstBlock(b, module)
					for _, result := range internalResults.All() {
						if !scanner.includeIgnored && module.Ignores().Covering(
							result.Range(),
							scanner.workspaceName,
							result.RuleID,
							result.LegacyRuleID,
						) != nil {
							metrics.Add(metrics.IgnoredChecks, 1)
							debug.Log("Ignoring '%s'", result.RuleID)
							continue
						}
						results = append(results, result)
					}
				}()
			}
		}
	}
	hclCheckTime.Stop()

	filtered := scanner.filterResults(results)
	scanner.sortResults(filtered)
	return filtered
}

func (scanner *Scanner) filterResults(results []*result.Result) []*result.Result {
	var filtered []*result.Result
	for _, result := range results {
		if !scanner.includeIgnored && checkInList(result.RuleID, result.LegacyRuleID, scanner.excludedRuleIDs) {
			metrics.Add(metrics.IgnoredChecks, 1)
			debug.Log("Ignoring '%s'", result.RuleID)
		} else {
			filtered = append(filtered, result)
		}
	}
	return filtered
}

func (scanner *Scanner) sortResults(results []*result.Result) {
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
}
