package block

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/schema"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

type HCLBlock struct {
	hclBlock    *hcl.Block
	evalContext *hcl.EvalContext
	moduleBlock Block
}

func NewHCLBlock(hclBlock *hcl.Block, ctx *hcl.EvalContext, moduleBlock Block) Block {
	return &HCLBlock{
		evalContext: ctx,
		hclBlock:    hclBlock,
		moduleBlock: moduleBlock,
	}
}

func (block *HCLBlock) AttachEvalContext(ctx *hcl.EvalContext) {
	block.evalContext = ctx
}

func (block *HCLBlock) HasModuleBlock() bool {
	return block.moduleBlock != nil
}

func (block *HCLBlock) GetModuleBlock() (Block, error) {
	if block.HasModuleBlock() {
		return block.moduleBlock, nil
	}
	return nil, fmt.Errorf("the block does not have an associated module block")
}

func (block *HCLBlock) Type() string {
	return block.hclBlock.Type
}

func (block *HCLBlock) Labels() []string {
	return block.hclBlock.Labels
}

func (block *HCLBlock) Range() Range {
	if block == nil || block.hclBlock == nil {
		return Range{}
	}
	var r hcl.Range
	switch body := block.hclBlock.Body.(type) {
	case *hclsyntax.Body:
		r = body.SrcRange
	default:
		r = block.hclBlock.DefRange
		r.End = block.hclBlock.Body.MissingItemRange().End
	}
	return Range{
		Filename:  r.Filename,
		StartLine: r.Start.Line,
		EndLine:   r.End.Line,
	}
}

func (block *HCLBlock) GetFirstMatchingBlock(names ...string) Block {
	for _, name := range names {
		b := block.GetBlock(name)
		if b != nil {
			return b
		}
	}
	return nil
}

func (block *HCLBlock) getHCLBlocks() hcl.Blocks {
	var blocks hcl.Blocks
	switch body := block.hclBlock.Body.(type) {
	case *hclsyntax.Body:
		for _, b := range body.Blocks {
			blocks = append(blocks, b.AsHCLBlock())
		}
	default:
		content, _, diag := block.hclBlock.Body.PartialContent(schema.TerraformSchema_0_12)
		if diag == nil {
			blocks = content.Blocks
		}
	}
	return blocks
}

func (block *HCLBlock) getHCLAttributes() hcl.Attributes {
	switch body := block.hclBlock.Body.(type) {
	case *hclsyntax.Body:
		attributes := make(hcl.Attributes)
		for _, a := range body.Attributes {
			attributes[a.Name] = a.AsHCLAttribute()
		}
		return attributes
	default:
		_, body, diag := block.hclBlock.Body.PartialContent(schema.TerraformSchema_0_12)
		if diag != nil {
			return nil
		}
		attrs, diag := body.JustAttributes()
		if diag != nil {
			return nil
		}
		return attrs
	}
}

func (block *HCLBlock) GetBlock(name string) Block {
	if block == nil || block.hclBlock == nil {
		return nil
	}
	for _, child := range block.getHCLBlocks() {
		if child.Type == name {
			return NewHCLBlock(child, block.evalContext, block.moduleBlock)
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

func (block *HCLBlock) AllBlocks() Blocks {
	if block == nil || block.hclBlock == nil {
		return nil
	}
	var results []Block
	for _, child := range block.getHCLBlocks() {
		results = append(results, NewHCLBlock(child, block.evalContext, block.moduleBlock))
	}
	return results
}

func (block *HCLBlock) GetBlocks(name string) Blocks {
	if block == nil || block.hclBlock == nil {
		return nil
	}
	var results []Block
	for _, child := range block.getHCLBlocks() {
		if child.Type == name {
			results = append(results, NewHCLBlock(child, block.evalContext, block.moduleBlock))
		}
		if child.Type == "dynamic" && len(child.Labels) == 1 && child.Labels[0] == name {
			dynamics := block.parseDynamicBlockResult(child)
			results = append(results, dynamics...)

		}
	}
	return results
}

func (block *HCLBlock) parseDynamicBlockResult(dynamic *hcl.Block) Blocks {

	var results Blocks

	wrapped := NewHCLBlock(dynamic, block.evalContext, block.moduleBlock)

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
		results = append(results, contentBlock)
	}

	return results
}

func (block *HCLBlock) GetAttributes() []Attribute {
	var results []Attribute
	if block == nil || block.hclBlock == nil {
		return nil
	}
	for _, attr := range block.getHCLAttributes() {
		results = append(results, NewHCLAttribute(attr, block.evalContext))
	}
	return results
}

func (block *HCLBlock) GetAttribute(name string) Attribute {
	if block == nil || block.hclBlock == nil {
		return nil
	}
	for _, attr := range block.getHCLAttributes() {
		if attr.Name == name {
			return NewHCLAttribute(attr, block.evalContext)
		}
	}
	return nil
}

func (block *HCLBlock) GetNestedAttribute(name string) Attribute {
	parts := strings.Split(name, "/")
	blocks := parts[:len(parts)-1]
	attrName := parts[len(parts)-1]

	var working Block = block
	for _, b := range blocks {
		if checkBlock := working.GetBlock(b); checkBlock == nil {
			return nil
		} else {
			working = checkBlock
		}
	}

	if working != nil {
		return working.GetAttribute(attrName)
	}

	return nil
}

func (block *HCLBlock) Reference() *Reference {

	var parts []string
	if block.Type() != "resource" {
		parts = append(parts, block.Type())
	}
	parts = append(parts, block.Labels()...)

	return newReference(parts)
}

// LocalName is the name relative to the current module
func (block *HCLBlock) LocalName() string {
	return block.Reference().String()
}

func (block *HCLBlock) FullName() string {

	if block.moduleBlock != nil {
		return fmt.Sprintf(
			"%s:%s",
			block.moduleBlock.FullName(),
			block.LocalName(),
		)
	}

	return block.LocalName()
}

func (block *HCLBlock) TypeLabel() string {
	if len(block.Labels()) > 0 {
		return block.Labels()[0]
	}
	return ""
}

func (block *HCLBlock) NameLabel() string {
	if len(block.Labels()) > 1 {
		return block.Labels()[1]
	}
	return ""
}

func (block *HCLBlock) HasChild(childElement string) bool {
	return block.GetAttribute(childElement) != nil || block.GetBlock(childElement) != nil
}

func (block *HCLBlock) MissingChild(childElement string) bool {
	return !block.HasChild(childElement)
}

func (block *HCLBlock) InModule() bool {
	return block.moduleBlock != nil
}

func (block *HCLBlock) Label() string {
	return strings.Join(block.hclBlock.Labels, ".")
}

func (block *HCLBlock) HasBlock(childElement string) bool {
	return block.GetBlock(childElement) != nil
}

func (block *HCLBlock) IsResourceType(resourceType string) bool {
	return block.TypeLabel() == resourceType
}

func (block *HCLBlock) IsEmpty() bool {
	return len(block.AllBlocks()) == 0 && len(block.GetAttributes()) == 0
}

func (block *HCLBlock) Attributes() map[string]Attribute {
	attributes := make(map[string]Attribute)
	for name, attr := range block.getHCLAttributes() {
		attributes[name] = NewHCLAttribute(attr, block.evalContext)
	}
	return attributes
}

func (block *HCLBlock) Values() cty.Value {

	values := make(map[string]cty.Value)
	for _, attribute := range block.getHCLAttributes() {
		func() {
			defer func() {
				if err := recover(); err != nil {
					return
				}
			}()
			val, _ := attribute.Expr.Value(block.evalContext)
			values[attribute.Name] = val
		}()
	}
	return cty.ObjectVal(values)
}
