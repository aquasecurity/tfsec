package scanner

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	internalDebug "github.com/tfsec/tfsec/internal/app/tfsec/debug"
	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// RuleCode is a unique identifier for a check
type RuleCode string

// RuleSummary is a summary description for a check
type RuleSummary string

// RuleProvider is the provider that the check applies to
type RuleProvider string

const (
	AWSProvider     RuleProvider = "aws"
	AzureProvider   RuleProvider = "azure"
	GCPProvider     RuleProvider = "google"
	GeneralProvider RuleProvider = "general"
)

// Check is a targeted security test which can be applied to terraform templates. It includes the types to run on e.g.
// "resource", and the labels to run on e.g. "aws_s3_bucket".
type Check struct {
	Code           RuleCode
	Documentation  CheckDocumentation
	Provider       RuleProvider
	RequiredTypes  []string
	RequiredLabels []string
	CheckFunc      func(*Check, *parser.Block, *Context) []Result
}

type CheckDocumentation struct {

	// Summary is a brief description of the check, e.g. "Unencrypted S3 Bucket"
	Summary RuleSummary

	// Explanation (markdown) contains reasoning for the check, details on it's value, and remediation info
	Explanation string

	// BadExample (hcl) contains Terraform code which would cause the check to fail
	BadExample string

	// GoodExample (hcl) modifies the BadExample content to cause the check to pass
	GoodExample string

	// Links are URLs which contain further reading related to the check
	Links []string
}

// Run runs the check against the provided HCL block, including the hclEvalContext to evaluate expressions if it is
// provided.
func (check *Check) Run(block *parser.Block, context *Context) []Result {
	defer func() {
		if err := recover(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "WARNING: skipped %s check due to error(s): %s\n", check.Code, err)
			internalDebug.Log("Stack trace for failed %s check:\n%s\n\n", check.Code, string(debug.Stack()))
		}
	}()
	results := check.CheckFunc(check, block, context)
	if check.Provider == "custom" {
		for i := range results { // populate custom check results with relatedLinks
			if len(check.Documentation.Links) > 0 {
				results[i].Link = fmt.Sprintf("See the following link(s) for more information:\n\n   %s", strings.Join(check.Documentation.Links, "\n   "))
			}
		}
	} else {
		for i := range results { // supplement results with links to documentation site
			results[i].Link = fmt.Sprintf("See https://tfsec.dev/docs/%s/%s/ for more information.", check.Provider, check.Code)
		}
	}
	return results
}

// IsRequiredForBlock returns true if the Check should be applied to the given HCL block
func (check *Check) IsRequiredForBlock(block *parser.Block) bool {

	if check.CheckFunc == nil {
		return false
	}

	if len(check.RequiredTypes) > 0 {
		var found bool
		for _, requiredType := range check.RequiredTypes {
			if block.Type() == requiredType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(check.RequiredLabels) > 0 {
		var found bool
		for _, requiredLabel := range check.RequiredLabels {
			if requiredLabel == "*" || (len(block.Labels()) > 0 && block.TypeLabel() == requiredLabel) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// NewResult creates a new Result, containing the given description and range
func (check *Check) NewResult(description string, r parser.Range, severity Severity) Result {
	return Result{
		RuleID:          check.Code,
		RuleDescription: check.Documentation.Summary,
		RuleProvider:    check.Provider,
		Description:     description,
		Range:           r,
		Severity:        severity,
	}
}

func (check *Check) NewResultWithValueAnnotation(description string, r parser.Range, attr *parser.Attribute, severity Severity) Result {

	if attr == nil || attr.IsLiteral() {
		return check.NewResult(description, r, severity)
	}

	var raw interface{}

	var typeStr string

	switch attr.Type() {
	case cty.String:
		raw = attr.Value().AsString()
		typeStr = "string"
	case cty.Bool:
		raw = attr.Value().True()
		typeStr = "bool"
	case cty.Number:
		raw, _ = attr.Value().AsBigFloat().Float64()
		typeStr = "number"
	default:
		return check.NewResult(description, r, severity)
	}

	return Result{
		RuleID:          check.Code,
		RuleDescription: check.Documentation.Summary,
		RuleProvider:    check.Provider,
		Description:     description,
		Range:           r,
		RangeAnnotation: fmt.Sprintf("[%s] %#v", typeStr, raw),
		Severity:        severity,
	}
}
