package result

import (
	"fmt"

	"github.com/aquasecurity/defsec/definition"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/severity"
)

// Result is a positive result for a security check. It encapsulates a code unique to the specific check it was raised
// by, a human-readable description and a range
type Result struct {
	RuleID          string            `json:"rule_id"`
	LegacyRuleID    string            `json:"legacy_rule_id"`
	RuleSummary     string            `json:"rule_description"`
	RuleProvider    provider.Provider `json:"rule_provider"`
	Impact          string            `json:"impact"`
	Resolution      string            `json:"resolution"`
	Links           []string          `json:"links"`
	Description     string            `json:"description"`
	RangeAnnotation string            `json:"-"`
	Severity        severity.Severity `json:"severity"`
	Status          Status            `json:"status"`
	Location        definition.Range  `json:"location"`
}

type Status string

const (
	Failed  Status = "failed"
	Passed  Status = "passed"
	Ignored Status = "ignored"
)

func New() *Result {
	result := &Result{
		Status: Failed,
	}
	return result
}

func (r *Result) Passed() bool {
	return r.Status == Passed
}

func (r *Result) Range() definition.Range {
	return r.Location
}

func (r *Result) HashCode() string {

	return fmt.Sprintf("%s:%s", r.Location, r.RuleID)
}

func (r *Result) WithRuleID(id string) *Result {
	r.RuleID = id
	return r
}

func (r *Result) WithLegacyRuleID(id string) *Result {
	r.LegacyRuleID = id
	return r
}

func (r *Result) WithRuleSummary(description string) *Result {
	r.RuleSummary = description
	return r
}

func (r *Result) WithRuleProvider(provider provider.Provider) *Result {
	r.RuleProvider = provider
	return r
}

func (r *Result) WithImpact(impact string) *Result {
	r.Impact = impact
	return r
}

func (r *Result) WithResolution(resolution string) *Result {
	r.Resolution = resolution
	return r
}

func (r *Result) WithLink(link string) *Result {
	r.Links = append(r.Links, link)
	return r
}

func (r *Result) WithLinks(links []string) *Result {
	r.Links = links
	return r
}

func (r *Result) WithDescription(description string, parts ...interface{}) *Result {
	if len(parts) == 0 {
		r.Description = description
	} else {
		r.Description = fmt.Sprintf(description, parts...)
	}

	return r
}

func (r *Result) WithSeverity(sev severity.Severity) *Result {
	r.Severity = sev
	return r
}

func (r *Result) WithStatus(status Status) *Result {
	r.Status = status
	return r
}

func (r *Result) WithAttribute(attr string) *Result {
	return r
}

func (r *Result) WithBlock(block string) *Result {
	return r
}

func(r *Result) WithRange(ra definition.Range) *Result {
	r.Location = ra
	return r
}
