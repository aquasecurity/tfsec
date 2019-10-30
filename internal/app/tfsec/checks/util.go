package checks

import (
	"strings"

	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

func getAttribute(block *hcl.Block, ctx *hcl.EvalContext, name string) (cty.Value, *Range, bool) {

	attributes, _ := block.Body.JustAttributes()

	for _, attribute := range attributes {
		if attribute.Name == name {
			val, diagnostics := attribute.Expr.Value(ctx)
			if diagnostics != nil && diagnostics.HasErrors() {
				return cty.NilVal, nil, false
			}
			return val, convertRange(attribute.Range), true
		}
	}

	return cty.NilVal, nil, false
}

func getBlock(block *hcl.Block, name string) (*hcl.Block, bool) {
	hclBody, ok := block.Body.(*hclsyntax.Body)
	if !ok {
		return nil, false
	}
	for _, hclBlock := range hclBody.Blocks {
		if hclBlock.Type == name {
			return hclBlock.AsHCLBlock(), true
		}
	}
	return nil, false
}

func getBlockName(block *hcl.Block) string {
	var prefix string
	if block.Type != "resource" {
		prefix = block.Type
	}
	return prefix + strings.Join(block.Labels, ".")
}

func convertRange(r hcl.Range) *Range {
	return &Range{
		Filename:  r.Filename,
		StartLine: r.Start.Line,
		EndLine:   r.End.Line,
	}
}

func isSensitiveName(name string) bool {

	// TODO add a whole bunch of regular expressions in here

	name = strings.ToLower(name)

	switch {
	case
		strings.Contains(name, "password"),
		strings.Contains(name, "secret"),
		strings.Contains(name, "private_key"),
		strings.Contains(name, "aws_access_key_id"),
		strings.Contains(name, "aws_secret_access_key"),
		strings.Contains(name, "token"),
		strings.Contains(name, "api_key"):
		return true
	}

	return false
}
