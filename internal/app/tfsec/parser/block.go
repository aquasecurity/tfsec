package parser

import (
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

type Block struct {
	hclBlock *hcl.Block
	ctx      *hcl.EvalContext
}

type Blocks []*Block

func (blocks Blocks) OfType(t string) Blocks {
	var results []*Block
	for _, block := range blocks {
		if block.Type() == t {
			results = append(results, block)
		}
	}
	return results
}

func NewBlock(hclBlock *hcl.Block, ctx *hcl.EvalContext) *Block {
	return &Block{
		hclBlock: hclBlock,
		ctx:      ctx,
	}
}

func (block *Block) body() *hclsyntax.Body {
	return block.hclBlock.Body.(*hclsyntax.Body)
}

func (block *Block) Type() string {
	return block.hclBlock.Type
}

func (block *Block) Labels() []string {
	return block.hclBlock.Labels
}

func (block *Block) Range() Range {
	if block == nil || block.hclBlock == nil {
		return Range{}
	}
	r := block.body().SrcRange
	return Range{
		Filename:  r.Filename,
		StartLine: r.Start.Line,
		EndLine:   r.End.Line,
	}
}

func (block *Block) GetBlock(name string) *Block {
	if block == nil || block.hclBlock == nil {
		return nil
	}
	for _, child := range block.body().Blocks {
		if child.Type == name {
			return NewBlock(child.AsHCLBlock(), block.ctx)
		}
	}
	return nil
}

func (block *Block) GetAttributes() []*Attribute {
	var results []*Attribute
	if block == nil || block.hclBlock == nil {
		return nil
	}
	for _, attr := range block.body().Attributes {
		results = append(results, NewAttribute(attr, block.ctx))
	}
	return results
}

func (block *Block) GetAttribute(name string) *Attribute {
	if block == nil || block.hclBlock == nil {
		return nil
	}
	for _, attr := range block.body().Attributes {
		if attr.Name == name {
			return NewAttribute(attr, block.ctx)
		}
	}
	return nil
}

func (block *Block) Name() string {
	var prefix string
	if block.Type() != "resource" {
		prefix = block.Type()
	}
	return prefix + strings.Join(block.Labels(), ".")
}
