package parser

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

type Block struct {
	hclBlock *hcl.Block
	ctx      *hcl.EvalContext
	prefix   string
	inModule bool
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

func (blocks Blocks) RemoveDuplicates() Blocks {
	filtered := make(map[string]Block)
	for _, block := range blocks {
		filtered[block.identifier()] = *block
	}
	var blockSet Blocks
	for key := range filtered {
		block := filtered[key]
		blockSet = append(blockSet, &block)
	}
	return blockSet
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
		if child.Type == "dynamic" && len(child.Labels) == 1 && child.Labels[0] == name {
			blocks := block.parseDynamicBlockResult(child)
			if len(blocks) > 0 {
				return blocks[0]
			}
			return nil
		}
	}
	return nil
}

func (block *Block) GetBlocks(name string) Blocks {
	if block == nil || block.hclBlock == nil {
		return nil
	}
	var results []*Block
	for _, child := range block.body().Blocks {
		if child.Type == name {
			results = append(results, NewBlock(child.AsHCLBlock(), block.ctx))
		}
		if child.Type == "dynamic" && len(child.Labels) == 1 && child.Labels[0] == name {
			dynamics := block.parseDynamicBlockResult(child)
			results = append(results, dynamics...)

		}
	}
	return results
}

func (block *Block) parseDynamicBlockResult(dynamic *hclsyntax.Block) Blocks {

	var results Blocks

	wrapped := NewBlock(dynamic.AsHCLBlock(), block.ctx)

	forEach := wrapped.GetAttribute("for_each")
	if forEach == nil {
		return nil
	}

	contentBlock := wrapped.GetBlock("content")
	if contentBlock == nil {
		return nil
	}

	values := forEach.Value().AsValueSlice()
	for range values {
		clone := *contentBlock
		results = append(results, &clone)
	}

	return results
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
		prefix = block.Type() + "."
	}
	if block.Type() == "output" && block.inModule {
		prefix = fmt.Sprintf("%s.", block.prefix)
	}
	return prefix + strings.Join(block.Labels(), ".")
}

func (block *Block) HasChild(childElement string) bool {
	return block.GetAttribute(childElement) != nil || block.GetBlock(childElement) != nil
}

func (block *Block) InModule() bool {
	return block.inModule
}

func (block *Block) identifier() string {
	return fmt.Sprintf("%s:%s:%s", block.Range().Filename, block.Type(), strings.Join(block.Labels(), ":"))
}
