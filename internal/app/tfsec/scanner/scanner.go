package scanner

import (
	"sort"

	"github.com/aquasecurity/defsec/types"
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

func (scanner *Scanner) Scan(modules []block.Module) []types.Result {

	adaptationTime := metrics.Start(metrics.Adaptation)
	infra := adapter.Adapt(modules)
	adaptationTime.Stop()

	var results []types.Result

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

	var ignores block.Ignores

	// run internal checks
	hclCheckTime := metrics.Start(metrics.HCLChecks)
	for _, module := range modules {
		ignores = append(ignores, module.Ignores()...)
		for _, b := range module.GetBlocks() {
			for _, r := range GetRegisteredRules() {
				func() {
					if scanner.ignoreCheckErrors {
						defer r.RecoverFromCheckPanic()
					}
					internalResults := r.CheckAgainstBlock(b, module)
					results = append(results, internalResults.All()...)
				}()
			}
		}
	}
	hclCheckTime.Stop()

	var resultsAfterIgnores []types.Result
	for _, result := range results {
		if !scanner.includeIgnored && ignores.Covering(
			result.Range(),
			scanner.workspaceName,
			result.RuleID,
			result.LegacyRuleID,
		) != nil {
			metrics.Add(metrics.IgnoredChecks, 1)
			debug.Log("Ignoring '%s'", result.RuleID)
			continue
		}
		resultsAfterIgnores = append(resultsAfterIgnores, result)
	}

	filtered := scanner.filterResults(resultsAfterIgnores)
	scanner.sortResults(filtered)
	return filtered
}

func (scanner *Scanner) filterResults(results []types.Result) []types.Result {
	var filtered []types.Result
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

func (scanner *Scanner) sortResults(results []types.Result) {
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
