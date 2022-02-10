package scanner

import (
	"runtime"
	"sort"

	adapter "github.com/aquasecurity/defsec/adapters/terraform"
	"github.com/aquasecurity/defsec/metrics"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/pkg/debug"
	"github.com/aquasecurity/tfsec/internal/pkg/legacy"
	"github.com/aquasecurity/trivy-config-parsers/terraform"
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

func (scanner *Scanner) Scan(modules terraform.Modules) (rules.Results, error) {

	adaptationTimer := metrics.Timer("timings", "adaptation")
	adaptationTimer.Start()
	infra := adapter.Adapt(modules)
	adaptationTimer.Stop()

	threads := runtime.NumCPU()
	if threads > 1 {
		threads--
	}
	if scanner.useSingleThread {
		threads = 1
	}

	checkTimer := metrics.Timer("timings", "running checks")
	checkTimer.Start()
	results, err := NewPool(threads, GetRegisteredRules(), modules, infra, scanner.ignoreCheckErrors).Run()
	if err != nil {
		return nil, err
	}
	checkTimer.Stop()

	var resultsAfterIgnores []rules.Result
	if !scanner.includeIgnored {
		var ignores terraform.Ignores
		for _, module := range modules {
			ignores = append(ignores, module.Ignores()...)
		}

		for _, result := range results {
			if !scanner.includeIgnored && ignores.Covering(
				modules,
				result.Metadata(),
				scanner.workspaceName,
				result.Rule().LongID(),
				legacy.FindID(result.Rule().LongID()),
			) != nil {
				debug.Log("Ignoring '%s'", result.Rule().LongID())
				continue
			}
			resultsAfterIgnores = append(resultsAfterIgnores, result)
		}
	} else {
		resultsAfterIgnores = results
	}

	metrics.Counter("results", "ignored").Increment(len(results) - len(resultsAfterIgnores))

	filtered := scanner.filterResults(resultsAfterIgnores)
	scanner.sortResults(filtered)
	return filtered, nil
}

func (scanner *Scanner) filterResults(results []rules.Result) []rules.Result {
	var filtered []rules.Result
	excludeCounter := metrics.Counter("results", "excluded")
	for _, result := range results {
		if len(scanner.includedRuleIDs) == 0 || len(scanner.includedRuleIDs) > 0 && checkInList(result.Rule().LongID(), legacy.FindID(result.Rule().LongID()), scanner.includedRuleIDs) {
			if !scanner.includeIgnored && checkInList(result.Rule().LongID(), legacy.FindID(result.Rule().LongID()), scanner.excludedRuleIDs) {
				excludeCounter.Increment(1)
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
			return results[i].Range().String() > results[j].Range().String()
		}
	})
}
