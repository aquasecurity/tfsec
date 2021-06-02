package scanner

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"
	"github.com/tfsec/tfsec/pkg/severity"
	"github.com/zclconf/go-cty/cty"
)

// NewResult creates a new Result, containing the given description and range
func NewResult(description string, blockRange block.Range, severity severity.Severity) result.Result {
	res := result.New().
		WithDescription(description).
		WithRange(blockRange).
		WithSeverity(severity)
	return *res
}

func NewPassingResult(codeRange block.Range) result.Result {
	res := result.New().
		WithRange(codeRange).
		WithSeverity(severity.None).
		WithStatus(result.Passed)
	return *res
}

func NewResultWithValueAnnotation(description string, codeRange block.Range, attr *block.Attribute, severity severity.Severity) result.Result {

	if attr == nil || attr.IsLiteral() {
		return NewResult(description, codeRange, severity)
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
		return NewResult(description, codeRange, severity)
	}

	res := result.New().
		WithDescription(description).
		WithRange(codeRange).
		WithRangeAnnotation(fmt.Sprintf("[%s] %#v", typeStr, raw)).
		WithSeverity(severity)
	return *res
}
