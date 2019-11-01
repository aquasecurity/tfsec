package parser

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
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

func (attr *Attribute) Type() cty.Type {
	return attr.Value().Type()
}

func (attr *Attribute) Value() cty.Value {
	if attr == nil {
		return cty.NilVal
	}
	ctyVal, _ := attr.hclAttribute.Expr.Value(attr.ctx)
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
