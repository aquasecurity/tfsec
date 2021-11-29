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
	LegacyRuleID    string            `json:"legacy_rule_id"`
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
	Location        block.Range       `json:"location"`
	Resource        string            `json:"resource"`
	blocks          block.Blocks
	attribute       block.Attribute
}

type Status string

const (
	Failed  Status = "failed"
	Passed  Status = "passed"
	Ignored Status = "ignored"
)

func New(resourceBlock block.Block) *Result {
	result := &Result{
		Status: Failed,
		blocks: []block.Block{resourceBlock},
	}
	result.Location = result.Range()
	if resourceBlock != nil && resourceBlock.Reference() != nil {
		result.Resource = resourceBlock.Reference().String()
	}
	return result
}

func (r *Result) Passed() bool {
	return r.Status == Passed
}

func (r *Result) Blocks() block.Blocks {
	return r.blocks
}

func (r *Result) IsOnAttribute() bool {
	return r.attribute != nil
}

func (r *Result) Range() block.Range {
	if r.attribute != nil {
		return r.attribute.Range()
	}
	return r.blocks[len(r.blocks)-1].Range()
}

func (r *Result) HashCode() string {
	var hash string
	for _, block := range r.blocks {
		hash += "!" + block.UniqueName()
	}
	if r.attribute != nil {
		hash += ":" + r.attribute.Name() + ":" + r.attribute.Range().String()
	}
	return fmt.Sprintf("%s:%s", hash, r.RuleID)
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

func (r *Result) WithRuleService(service string) *Result {
	r.RuleService = service
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

func (r *Result) WithBlock(block block.Block) *Result {
	if block.IsNil() {
		return r
	}
	r.blocks = append(r.blocks, block)
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

func (r *Result) WithAttribute(attr block.Attribute) *Result {

	if attr.IsNil() {
		return r
	}

	r.attribute = attr

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
		default:
			typeStr = "unknown"
			raw = "???"
		}
	}

	r.RangeAnnotation = fmt.Sprintf("%s: %s", typeStr, raw)
	r.Location = r.Range()
	return r
}
