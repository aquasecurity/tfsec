package rules

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/severity"
)

type FlatResult struct {
	RuleID          string            `json:"rule_id"`
	RuleSummary     string            `json:"rule_description"`
	RuleProvider    provider.Provider `json:"rule_provider"`
	Impact          string            `json:"impact"`
	Resolution      string            `json:"resolution"`
	Links           []string          `json:"links"`
	Description     string            `json:"description"`
	RangeAnnotation string            `json:"-"`
	Severity        severity.Severity `json:"severity"`
	Status          Status            `json:"status"`
	Location        FlatRange         `json:"location"`
}

type FlatRange struct {
	Filename  string `json:"filename"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

func (r Results) Flatten() []FlatResult {
	var results []FlatResult
	for _, original := range r {
		results = append(results, original.Flatten())
	}
	return results
}

func (r *Result) Flatten() FlatResult {
	return FlatResult{
		RuleID:          r.rule.ID,
		RuleSummary:     r.rule.Summary,
		RuleProvider:    r.rule.Provider,
		Impact:          r.rule.ID,
		Resolution:      r.rule.Resolution,
		Links:           r.rule.Links,
		Description:     r.Description(),
		RangeAnnotation: r.Annotation(),
		Severity:        r.rule.Severity,
		Status:          r.status,
		Location: FlatRange{
			Filename:  r.metadata.Range().GetFilename(),
			StartLine: r.metadata.Range().GetStartLine(),
			EndLine:   r.metadata.Range().GetEndLine(),
		},
	}
}
