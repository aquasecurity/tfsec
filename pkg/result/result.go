package result

import (
	"fmt"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

// Result is a positive result for a security check. It encapsulates a code unique to the specific check it was raised
// by, a human-readable description and a range
type Result struct {
	RuleID          string            `json:"rule_id"`
	RuleSummary     string            `json:"rule_description"`
	RuleProvider    provider.Provider `json:"rule_provider"`
	Impact          string            `json:"impact"`
	Resolution      string            `json:"resolution"`
	Links           []string          `json:"links"`
	Range           block.Range       `json:"location"`
	Description     string            `json:"description"`
	RangeAnnotation string            `json:"-"`
	Severity        severity.Severity `json:"severity"`
	Status          Status            `json:"status"`
	topLevelBlock   block.Block
}

type Status string

const (
	Failed  Status = "failed"
	Passed  Status = "passed"
	Ignored Status = "ignored"
)

func New(resourceBlock block.Block) *Result {
	return &Result{
		Status:        Failed,
		topLevelBlock: resourceBlock,
	}
}

func (r *Result) Passed() bool {
	return r.Status == Passed
}

func (r *Result) HashCode() string {
	return fmt.Sprintf("%s:%s", r.Range, r.RuleID)
}

func (r *Result) WithRuleID(id string) *Result {
	r.RuleID = id
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

func (r *Result) WithRange(codeRange block.Range) *Result {
	r.Range = codeRange
	return r
}

func (r *Result) WithDescription(description string) *Result {
	r.Description = description
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

func (r *Result) WithAttributeAnnotation(attr block.Attribute) *Result {

	var raw string

	var typeStr string

	typ := attr.Type()

	switch typ {
	case cty.String:
		raw = fmt.Sprintf("%q", attr.Value().AsString())
		typeStr = "string"
	case cty.Bool:
		raw = fmt.Sprintf("%t", attr.Value().True())
		typeStr = "bool"
	case cty.Number:
		float, _ := attr.Value().AsBigFloat().Float64()
		raw = fmt.Sprintf("%f", float)
		typeStr = "number"
	default:
		switch true {
		case typ.IsTupleType(), typ.IsListType():
			values := attr.Value().AsValueSlice()
			var strValues []string
			for _, value := range values {
				switch value.Type() {
				case cty.String:
					strValues = append(strValues, fmt.Sprintf("%q", value.AsString()))
				case cty.Number:
					strValues = append(strValues, fmt.Sprintf(`%f`, value.AsBigFloat()))
				case cty.Bool:
					strValues = append(strValues, fmt.Sprintf(`%t`, value.True()))
				}

			}
			typeStr = "list"
			raw = fmt.Sprintf("[%s]", strings.Join(strValues, ", "))
		}
	}

	r.RangeAnnotation = fmt.Sprintf("%s: %s", typeStr, raw)
	return r
}
