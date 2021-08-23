package result

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/severity"
)

type Set interface {
	Add(result *Result)
	AddResult() *Result
	WithRuleID(id string) Set
	WithLegacyRuleID(id string) Set
	WithRuleSummary(description string) Set
	WithRuleProvider(provider provider.Provider) Set
	WithImpact(impact string) Set
	WithResolution(resolution string) Set
	WithLinks(links []string) Set
	WithSeverity(severity.Severity) Set
	All() []Result
}

func NewSet() *resultSet {
	return &resultSet{}
}

type resultSet struct {
	results      []Result
	ruleID       string
	legacyID     string
	ruleSummary  string
	ruleProvider provider.Provider
	impact       string
	resolution   string
	links        []string
	severity     severity.Severity
}

func (s *resultSet) Add(r *Result) {

	if r == nil {
		return
	}

	r.WithRuleID(s.ruleID).
		WithLegacyRuleID(s.legacyID).
		WithRuleSummary(s.ruleSummary).
		WithImpact(s.impact).
		WithResolution(s.resolution).
		WithRuleProvider(s.ruleProvider).
		WithLinks(s.links)

	if r.Severity == severity.None {
		r.WithSeverity(s.severity)
	}

	s.results = append(s.results, *r)
}

func (s *resultSet) WithSeverity(severity severity.Severity) Set {
	s.severity = severity
	return s
}

func (s *resultSet) AddResult() *Result {
	result := New().
		WithRuleID(s.ruleID).
		WithLegacyRuleID(s.legacyID).
		WithRuleSummary(s.ruleSummary).
		WithImpact(s.impact).
		WithResolution(s.resolution).
		WithRuleProvider(s.ruleProvider).
		WithLinks(s.links)
	s.results = append(s.results, *result)
	return result
}

func (s *resultSet) All() []Result {
	return s.results
}

func (r *resultSet) WithRuleID(id string) Set {
	r.ruleID = id
	return r
}

func (r *resultSet) WithLegacyRuleID(id string) Set {
	r.legacyID = id
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
