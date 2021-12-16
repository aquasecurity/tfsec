package scanner

import (
	"runtime"
	"sort"

	"github.com/aquasecurity/defsec/rules"
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
	includedRuleIDs   []string
	ignoreCheckErrors bool
	workspaceName     string
	useSingleThread   bool
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

func FindLegacyID(longID string) string {
	for _, rule := range GetRegisteredRules() {
		if rule.ID() == longID {
			return rule.LegacyID
		}
	}
	return ""
}

func (scanner *Scanner) Scan(modules []block.Module) (rules.Results, error) {

	adaptationTime := metrics.Start(metrics.Adaptation)
	infra := adapter.Adapt(modules)
	adaptationTime.Stop()

	threads := runtime.NumCPU()
	if threads > 1 {
		threads = threads - 1
	}
	if scanner.useSingleThread {
		threads = 1
	}

	checkTime := metrics.Start(metrics.Checking)
	results, err := NewPool(threads, GetRegisteredRules(), modules, infra, scanner.ignoreCheckErrors).Run()
	if err != nil {
		return nil, err
	}
	checkTime.Stop()

	var resultsAfterIgnores []rules.Result
	if !scanner.includeIgnored {
		var ignores block.Ignores
		for _, module := range modules {
			ignores = append(ignores, module.Ignores()...)
		}

		for _, result := range results {
			if !scanner.includeIgnored && ignores.Covering(
				result.NarrowestRange(),
				scanner.workspaceName,
				result.Rule().LongID(),
				FindLegacyID(result.Rule().LongID()),
			) != nil {
				metrics.Add(metrics.IgnoredChecks, 1)
				debug.Log("Ignoring '%s'", result.Rule().LongID())
				continue
			}
			resultsAfterIgnores = append(resultsAfterIgnores, result)
		}
	} else {
		resultsAfterIgnores = results
	}

	filtered := scanner.filterResults(resultsAfterIgnores)
	scanner.sortResults(filtered)
	return filtered, nil
}

func (scanner *Scanner) filterResults(results []rules.Result) []rules.Result {
	var filtered []rules.Result
	for _, result := range results {
		if len(scanner.includedRuleIDs) == 0 || len(scanner.includedRuleIDs) > 0 && checkInList(result.Rule().LongID(), FindLegacyID(result.Rule().LongID()), scanner.includedRuleIDs) {
			if !scanner.includeIgnored && checkInList(result.Rule().LongID(), FindLegacyID(result.Rule().LongID()), scanner.excludedRuleIDs) {
				metrics.Add(metrics.IgnoredChecks, 1)
				debug.Log("Ignoring '%s'", result.Rule().LongID())
			} else if scanner.includePassed || result.Status() != rules.StatusPassed {
				filtered = append(filtered, result)
			}
		}
	}
	return filtered
}

func (scanner *Scanner) sortResults(results []rules.Result) {
	sort.Slice(results, func(i, j int) bool {
		switch {
		case results[i].Rule().LongID() < results[j].Rule().LongID():
			return true
		case results[i].Rule().LongID() > results[j].Rule().LongID():
			return false
		default:
			return results[i].NarrowestRange().String() > results[j].NarrowestRange().String()
		}
	})
}
