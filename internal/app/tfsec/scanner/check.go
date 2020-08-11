package scanner

import (
	"fmt"
	"os"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// RuleID is a unique identifier for a check
type RuleID string

// Check is a targeted security test which can be applied to terraform templates. It includes the types to run on e.g.
// "resource", and the labels to run on e.g. "aws_s3_bucket".
type Check struct {
	Code           RuleID
	RequiredTypes  []string
	RequiredLabels []string
	CheckFunc      func(*Check, *parser.Block, *Context) []Result
}

// Run runs the check against the provided HCL block, including the hclEvalContext to evaluate expressions if it is
// provided.
func (check *Check) Run(block *parser.Block, context *Context) []Result {
	defer func() {
		if err := recover(); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: skipped %s check due to error(s): %s\n", check.Code, err)
		}
	}()
	return check.CheckFunc(check, block, context)
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
			if len(block.Labels()) > 0 && block.Labels()[0] == requiredLabel {
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
		RuleID:      check.Code,
		Description: description,
		Range:       r,
		Severity:    severity,
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
		Description:     description,
		Range:           r,
		RangeAnnotation: fmt.Sprintf("[%s] %#v", typeStr, raw),
	}
}
