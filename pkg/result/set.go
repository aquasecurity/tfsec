package result

import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/provider"
)

type Set interface {
	AddResult() *Result
	WithRuleID(id string) Set
	WithLegacyRuleID(id string) Set
	WithRuleSummary(description string) Set
	WithRuleProvider(provider provider.Provider) Set
	WithRuleService(service string) Set
	WithImpact(impact string) Set
	WithResolution(resolution string) Set
	WithLinks(links []string) Set
	All() []*Result
}

func NewSet(resourceBlock block.Block) *resultSet {
	return &resultSet{
		resourceBlock: resourceBlock,
	}
}

type resultSet struct {
	resourceBlock block.Block
	results       []*Result
	ruleID        string
	legacyID      string
	ruleSummary   string
	ruleProvider  provider.Provider
	ruleService   string
	impact        string
	resolution    string
	links         []string
}

func (s *resultSet) AddResult() *Result {
	result := New(s.resourceBlock).
		WithRuleID(s.ruleID).
		WithLegacyRuleID(s.legacyID).
		WithRuleSummary(s.ruleSummary).
		WithImpact(s.impact).
		WithResolution(s.resolution).
		WithRuleProvider(s.ruleProvider).
		WithRuleService(s.ruleService).
		WithLinks(s.links)
	s.results = append(s.results, result)
	return result
}

func (s *resultSet) All() []*Result {
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

func (r *resultSet) WithRuleService(service string) Set {
	r.ruleService = service
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
