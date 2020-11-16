package parser

import (
	"fmt"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/tfsec/tfsec/internal/app/tfsec/debug"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
	"regexp"
	"strings"
)

type Attribute struct {
	hclAttribute *hclsyntax.Attribute
	ctx          *hcl.EvalContext
}

func NewAttribute(attr *hclsyntax.Attribute, ctx *hcl.EvalContext) *Attribute {
	return &Attribute{
		hclAttribute: attr,
		ctx:          ctx,
	}
}

func (attr *Attribute) IsLiteral() bool {
	return len(attr.hclAttribute.Expr.Variables()) == 0
}

func (attr *Attribute) Type() cty.Type {
	return attr.Value().Type()
}

func (attr *Attribute) Value() cty.Value {
	if attr == nil {
		return cty.NilVal
	}
	ctyVal, _ := attr.hclAttribute.Expr.Value(attr.ctx)
	if !ctyVal.IsKnown() {
		return cty.NilVal
	}
	return ctyVal
}

func (attr *Attribute) Range() Range {
	return Range{
		Filename:  attr.hclAttribute.SrcRange.Filename,
		StartLine: attr.hclAttribute.SrcRange.Start.Line,
		EndLine:   attr.hclAttribute.SrcRange.End.Line,
	}
}

func (attr *Attribute) Name() string {
	return attr.hclAttribute.Name
}

func (attr *Attribute) Contains(checkValue interface{}) bool {
	val := attr.Value()
	if val.IsNull() {
		return false
	}
	if val.Type().IsObjectType() || val.Type().IsMapType() {
		valueMap := val.AsValueMap()
		for key := range valueMap {
			if key == checkValue {
				return true
			}
		}
		return false
	}
	if val.Type().IsListType() || val.Type().IsTupleType() {
		valueSlice := val.AsValueSlice()
		for _, value := range valueSlice {
			if value.AsString() == checkValue {
				return true
			}
		}
		return false
	}
	return strings.Contains(val.AsString(), fmt.Sprintf("%v", checkValue))
}

func (attr *Attribute) StartsWith(prefix interface{}) bool {
	if attr.Value().Type() == cty.String {
		return strings.HasPrefix(attr.Value().AsString(), fmt.Sprintf("%v", prefix))
	}
	return false
}

func (attr *Attribute) EndsWith(suffix interface{}) bool {
	if attr.Value().Type() == cty.String {
		return strings.HasSuffix(attr.Value().AsString(), fmt.Sprintf("%v", suffix))
	}
	return false
}

type EqualityOption int

const (
	IgnoreCase EqualityOption = iota
)

func (attr *Attribute) Equals(checkValue interface{}, equalityOptions ...EqualityOption) bool {
	if attr.Value().Type() == cty.String {
		for _, option := range equalityOptions {
			if option == IgnoreCase {
				return strings.EqualFold(strings.ToLower(attr.Value().AsString()), strings.ToLower(fmt.Sprintf("%v", checkValue)))
			}
		}
		return strings.EqualFold(attr.Value().AsString(), fmt.Sprintf("%v", checkValue))
	}
	if attr.Value().Type() == cty.Bool {
		return attr.Value().True() == checkValue
	}
	if attr.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			debug.Log("Error converting number for equality check. %s", err)
			return false
		}
		return attr.Value().RawEquals(checkNumber)
	}
	return false
}

func (attr *Attribute) RegexMatches(pattern interface{}) bool {
	patternVal := fmt.Sprintf("%v", pattern)
	re, err := regexp.Compile(patternVal)
	if err != nil {
		debug.Log("an error occurred while compiling the regex: %s", err)
		return false
	}
	if attr.Value().Type() == cty.String {
		match := re.MatchString(attr.Value().AsString())
		return match
	}
	return false
}

func (attr *Attribute) IsAny(options ...interface{}) bool {
	if attr.Value().Type() == cty.String {
		for _, option := range options {
			if option == attr.Value().AsString() {
				return true
			}
		}
	}
	if attr.Value().Type() == cty.Number {
		for _, option := range options {
			checkValue, err := gocty.ToCtyValue(option, cty.Number)
			if err != nil {
				debug.Log("Error converting number for equality check. %s", err)
				return false
			}
			if attr.Value().RawEquals(checkValue) {
				return true
			}
		}
	}
	return false
}

func (attr *Attribute) IsNone(options ...interface{}) bool {
	if attr.Value().Type() == cty.String {
		for _, option := range options {
			if option == attr.Value().AsString() {
				return false
			}
		}
	}
	if attr.Value().Type() == cty.Number {
		for _, option := range options {
			checkValue, err := gocty.ToCtyValue(option, cty.Number)
			if err != nil {
				debug.Log("Error converting number for equality check. %s", err)
				return false
			}
			if attr.Value().RawEquals(checkValue) {
				return false
			}

		}
	}

	return true
}

func (attr *Attribute) IsTrue() bool {
	return attr.Value().Type() == cty.Bool && attr.Value().True()
}

func (attr *Attribute) IsFalse() bool {
	return attr.Value().Type() == cty.Bool && attr.Value().False()
}

func (attr *Attribute) IsEmpty() bool {
	if attr.Value().Type() == cty.String {
		return len(attr.Value().AsString()) == 0
	}
	if attr.Type().IsListType() || attr.Type().IsTupleType() {
		return len(attr.Value().AsValueSlice()) == 0
	}
	if attr.Type().IsMapType() || attr.Type().IsObjectType() {
		return len(attr.Value().AsValueMap()) == 0
	}
	if attr.Value().Type() == cty.Number {
		// a number can't ever be empty
		return false
	}
	return true
}

func (attr *Attribute) MapValue(mapKey string) cty.Value {
	if attr.Type().IsObjectType() || attr.Type().IsMapType() {
		attrMap := attr.Value().AsValueMap()
		for key, value := range attrMap {
			if key == mapKey {
				return value
			}
		}
	}
	return cty.StringVal("")
}

func (attr *Attribute) LessThan(checkValue interface{}) bool {
	if attr.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			debug.Log("Error converting number for equality check. %s", err)
			return false
		}

		return attr.Value().LessThan(checkNumber).True()
	}
	return false
}

func (attr *Attribute) LessThanOrEqualTo(checkValue interface{}) bool {
	if attr.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			debug.Log("Error converting number for equality check. %s", err)
			return false
		}

		return attr.Value().LessThanOrEqualTo(checkNumber).True()
	}
	return false
}

func (attr *Attribute) GreaterThan(checkValue interface{}) bool {
	if attr.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			debug.Log("Error converting number for equality check. %s", err)
			return false
		}

		return attr.Value().GreaterThan(checkNumber).True()
	}
	return false
}

func (attr *Attribute) GreaterThanOrEqualTo(checkValue interface{}) bool {
	if attr.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			debug.Log("Error converting number for equality check. %s", err)
			return false
		}

		return attr.Value().GreaterThanOrEqualTo(checkNumber).True()
	}
	return false
}
