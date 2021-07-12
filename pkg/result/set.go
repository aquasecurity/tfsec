package result

import "github.com/aquasecurity/tfsec/pkg/provider"

type Set interface {
	Add(result *Result)
	WithRuleID(id string) Set
	WithRuleSummary(description string) Set
	WithRuleProvider(provider provider.Provider) Set
	WithImpact(impact string) Set
	WithResolution(resolution string) Set
	WithLinks(links []string) Set
	All() []Result
}

func NewSet() *resultSet {
	return &resultSet{}
}

type resultSet struct {
	results      []Result
	ruleID       string
	ruleSummary  string
	ruleProvider provider.Provider
	impact       string
	resolution   string
	links        []string
}

func (s *resultSet) Add(result *Result) {
	result.
		WithRuleID(s.ruleID).
		WithRuleSummary(s.ruleSummary).
		WithImpact(s.impact).
		WithResolution(s.resolution).
		WithRuleProvider(s.ruleProvider).
		WithLinks(s.links)

	if result.Range.Filename == "" {
		result.Range = result.topLevelBlock.Range()
	}

	s.results = append(s.results, *result)
}

func (s *resultSet) All() []Result {
	return s.results
}

func (r *resultSet) WithRuleID(id string) Set {
	r.ruleID = id
	return r
}

func (r *resultSet) WithRuleSummary(description string) Set {
	r.ruleSummary = description
	return r
}

func (r *resultSet) WithRuleProvider(provider provider.Provider) Set {
	r.ruleProvider = provider
	return r
}

func (r *resultSet) WithImpact(impact string) Set {
	r.impact = impact
	return r
}

func (r *resultSet) WithResolution(resolution string) Set {
	r.resolution = resolution
	return r
}

func (r *resultSet) WithLinks(links []string) Set {
	r.links = links
	return r
}
