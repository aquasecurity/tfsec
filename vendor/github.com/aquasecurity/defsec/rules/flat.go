package rules

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/severity"
)

type FlatResult struct {
	RuleID          string            `json:"rule_id"`
	RuleSummary     string            `json:"rule_description"`
	RuleProvider    provider.Provider `json:"rule_provider"`
	RuleService     string            `json:"rule_service"`
	Impact          string            `json:"impact"`
	Resolution      string            `json:"resolution"`
	Links           []string          `json:"links"`
	Description     string            `json:"description"`
	RangeAnnotation string            `json:"-"`
	Severity        severity.Severity `json:"severity"`
	Status          Status            `json:"status"`
	Resource        string            `json:"resource"`
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
	rng := r.CodeBlockMetadata().Range()
	if r.IssueBlockMetadata() != nil {
		rng = r.IssueBlockMetadata().Range()
	}
	return FlatResult{
		RuleID:          r.rule.AVDID,
		RuleSummary:     r.rule.Summary,
		RuleProvider:    r.rule.Provider,
		RuleService:     r.rule.Service,
		Impact:          r.rule.Impact,
		Resolution:      r.rule.Resolution,
		Links:           r.rule.Links,
		Description:     r.Description(),
		RangeAnnotation: r.Annotation(),
		Severity:        r.rule.Severity,
		Status:          r.status,
		Resource:        r.CodeBlockMetadata().Reference().LogicalID(),
		Location: FlatRange{
			Filename:  rng.GetFilename(),
			StartLine: rng.GetStartLine(),
			EndLine:   rng.GetEndLine(),
		},
	}
}
