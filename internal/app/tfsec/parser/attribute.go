package parser

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/tfsec/tfsec/internal/app/tfsec/debug"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
	"strconv"
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

func (attr *Attribute) Contains(checkValue string) bool {
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
	return strings.Contains(val.AsString(), checkValue)
}

func (attr *Attribute) StartsWith(prefix string) bool {
	if attr.Value().Type() == cty.String {
		return strings.HasPrefix(attr.Value().AsString(), prefix)
	}
	return false
}

func (attr *Attribute) EndsWith(prefix string) bool {
	if attr.Value().Type() == cty.String {
		return strings.HasSuffix(attr.Value().AsString(), prefix)
	}
	return false
}

func (attr *Attribute) Equals(checkValue string) bool {
	if attr.Value().Type() == cty.String {
		return strings.EqualFold(attr.Value().AsString(), checkValue)
	}
	if attr.Value().Type() == cty.Bool {
		checkBool, err := strconv.ParseBool(checkValue)
		if err != nil {
			debug.Log("Error converting bool for equality check. %s", err)
			return false
		}
		return attr.Value().True() == checkBool
	}
	if attr.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			debug.Log("Error converting bool for equality check. %s", err)
			return false
		}
		return attr.Value().RawEquals(checkNumber)
	}
	return false
}
