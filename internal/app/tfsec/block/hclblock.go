package block

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/schema"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
)

type HCLBlock struct {
	hclBlock    *hcl.Block
	evalContext *hcl.EvalContext
	moduleBlock Block
	expanded    bool
	cloneIndex  int
}

func NewHCLBlock(hclBlock *hcl.Block, ctx *hcl.EvalContext, moduleBlock Block) Block {
	return &HCLBlock{
		evalContext: ctx,
		hclBlock:    hclBlock,
		moduleBlock: moduleBlock,
	}
}

func (b *HCLBlock) markCountExpanded() {
	b.expanded = true
}

func (b *HCLBlock) IsCountExpanded() bool {
	return b.expanded
}

func (b *HCLBlock) Clone(index cty.Value) Block {
	var childCtx *hcl.EvalContext
	if b.evalContext != nil {
		childCtx = b.evalContext.NewChild()
	} else {
		childCtx = &hcl.EvalContext{}
	}

	if childCtx.Variables == nil {
		childCtx.Variables = make(map[string]cty.Value)
	}
	cloneHCL := *b.hclBlock

	clone := NewHCLBlock(&cloneHCL, childCtx, b.moduleBlock).(*HCLBlock)
	if len(clone.hclBlock.Labels) > 0 {
		position := len(clone.hclBlock.Labels) - 1
		labels := make([]string, len(clone.hclBlock.Labels))
		for i := 0; i < len(labels); i++ {
			labels[i] = clone.hclBlock.Labels[i]
		}
		if index.IsKnown() && !index.IsNull() {
			switch index.Type() {
			case cty.Number:
				f, _ := index.AsBigFloat().Float64()
				labels[position] = fmt.Sprintf("%s[%d]", clone.hclBlock.Labels[position], int(f))
			case cty.String:
				labels[position] = fmt.Sprintf("%s[%q]", clone.hclBlock.Labels[position], index.AsString())
			default:
				debug.Log("Invalid key type in iterable: %#v", index.Type())
				labels[position] = fmt.Sprintf("%s[%#v]", clone.hclBlock.Labels[position], index)
			}
		} else {
			labels[position] = fmt.Sprintf("%s[%d]", clone.hclBlock.Labels[position], b.cloneIndex)
		}
		clone.hclBlock.Labels = labels
	}
	indexVal, _ := gocty.ToCtyValue(index, cty.Number)
	clone.evalContext.Variables["count"] = cty.ObjectVal(map[string]cty.Value{
		"index": indexVal,
	})
	clone.markCountExpanded()
	b.cloneIndex++
	return clone
}

func (b *HCLBlock) Context() *hcl.EvalContext {
	return b.evalContext
}

func (b *HCLBlock) AttachEvalContext(ctx *hcl.EvalContext) {
	b.evalContext = ctx
}

func (b *HCLBlock) HasModuleBlock() bool {
	if b == nil {
		return false
	}
	return b.moduleBlock != nil
}

func (b *HCLBlock) GetModuleBlock() (Block, error) {
	if b.HasModuleBlock() {
		return b.moduleBlock, nil
	}
	return nil, fmt.Errorf("the block does not have an associated module block")
}

func (b *HCLBlock) Type() string {
	return b.hclBlock.Type
}

func (b *HCLBlock) Labels() []string {
	return b.hclBlock.Labels
}

func (b *HCLBlock) Range() Range {
	if b == nil || b.hclBlock == nil {
		return Range{}
	}
	var r hcl.Range
	switch body := b.hclBlock.Body.(type) {
	case *hclsyntax.Body:
		r = body.SrcRange
	default:
		r = b.hclBlock.DefRange
		r.End = b.hclBlock.Body.MissingItemRange().End
	}
	return Range{
		Filename:  r.Filename,
		StartLine: r.Start.Line,
		EndLine:   r.End.Line,
	}
}

func (b *HCLBlock) GetFirstMatchingBlock(names ...string) Block {
	var returnBlock *HCLBlock
	for _, name := range names {
		childBlock := b.GetBlock(name)
		if childBlock.IsNotNil() {
			return childBlock
		}
	}
	return returnBlock
}

func (b *HCLBlock) getHCLBlocks() hcl.Blocks {
	var blocks hcl.Blocks
	switch body := b.hclBlock.Body.(type) {
	case *hclsyntax.Body:
		for _, b := range body.Blocks {
			blocks = append(blocks, b.AsHCLBlock())
		}
	default:
		content, _, diag := b.hclBlock.Body.PartialContent(schema.TerraformSchema_0_12)
		if diag == nil {
			blocks = content.Blocks
		}
	}
	return blocks
}

func (b *HCLBlock) getHCLAttributes() hcl.Attributes {
	switch body := b.hclBlock.Body.(type) {
	case *hclsyntax.Body:
		attributes := make(hcl.Attributes)
		for _, a := range body.Attributes {
			attributes[a.Name] = a.AsHCLAttribute()
		}
		return attributes
	default:
		_, body, diag := b.hclBlock.Body.PartialContent(schema.TerraformSchema_0_12)
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

func (b *HCLBlock) GetBlock(name string) Block {
	var returnBlock *HCLBlock
	if b == nil || b.hclBlock == nil {
		return returnBlock
	}
	for _, child := range b.getHCLBlocks() {
		if child.Type == name {
			return NewHCLBlock(child, b.evalContext, b.moduleBlock)
		}
		if child.Type == "dynamic" && len(child.Labels) == 1 && child.Labels[0] == name {
			blocks := b.parseDynamicBlockResult(child)
			if len(blocks) > 0 {
				return blocks[0]
			}
			return returnBlock
		}
	}
	return returnBlock
}

func (b *HCLBlock) AllBlocks() Blocks {
	if b == nil || b.hclBlock == nil {
		return nil
	}
	var results []Block
	for _, child := range b.getHCLBlocks() {
		results = append(results, NewHCLBlock(child, b.evalContext, b.moduleBlock))
	}
	return results
}

func (b *HCLBlock) GetBlocks(name string) Blocks {
	if b == nil || b.hclBlock == nil {
		return nil
	}
	var results []Block
	for _, child := range b.getHCLBlocks() {
		if child.Type == name {
			results = append(results, NewHCLBlock(child, b.evalContext, b.moduleBlock))
		}
		if child.Type == "dynamic" && len(child.Labels) == 1 && child.Labels[0] == name {
			dynamics := b.parseDynamicBlockResult(child)
			results = append(results, dynamics...)

		}
	}
	return results
}

func (b *HCLBlock) parseDynamicBlockResult(dynamic *hcl.Block) Blocks {

	var results Blocks

	wrapped := NewHCLBlock(dynamic, b.evalContext, b.moduleBlock)

	forEach := wrapped.GetAttribute("for_each")
	if forEach == nil {
		return nil
	}

	contentBlock := wrapped.GetBlock("content")
	if contentBlock == nil {
		return nil
	}

	val := forEach.Value()

	if val.IsNull() || !val.IsKnown() {
		return nil
	}

	switch {
	case val.Type().IsListType(), val.Type().IsSetType(), val.Type().IsMapType():
		// all good
	default:
		return nil
	}

	values := forEach.Value().AsValueSlice()
	for range values {
		results = append(results, contentBlock)
	}

	return results
}

func (b *HCLBlock) GetAttributes() []Attribute {
	var results []Attribute
	if b == nil || b.hclBlock == nil {
		return nil
	}
	for _, attr := range b.getHCLAttributes() {
		results = append(results, NewHCLAttribute(attr, b.evalContext))
	}
	return results
}

func (b *HCLBlock) GetAttribute(name string) Attribute {
	var attr *HCLAttribute
	if b == nil || b.hclBlock == nil {
		return attr
	}
	for _, attr := range b.getHCLAttributes() {
		if attr.Name == name {
			return NewHCLAttribute(attr, b.evalContext)
		}
	}
	return attr
}

func (b *HCLBlock) GetNestedAttribute(name string) Attribute {

	var returnAttr *HCLAttribute
	parts := strings.Split(name, ".")
	blocks := parts[:len(parts)-1]
	attrName := parts[len(parts)-1]

	var working Block = b
	for _, subBlock := range blocks {
		if checkBlock := working.GetBlock(subBlock); checkBlock == nil {
			return returnAttr
		} else {
			working = checkBlock
		}
	}

	if working != nil {
		return working.GetAttribute(attrName)
	}

	return returnAttr
}

func (b *HCLBlock) Reference() *Reference {

	var parts []string
	if b.Type() != "resource" {
		parts = append(parts, b.Type())
	}
	parts = append(parts, b.Labels()...)
	ref, _ := newReference(parts)
	return ref
}

func (b *HCLBlock) ReadLines() (lines []string, comments []string, err error) {
	return b.Range().ReadLines(false)
}

// LocalName is the name relative to the current module
func (b *HCLBlock) LocalName() string {
	return b.Reference().String()
}

func (b *HCLBlock) FullName() string {

	if b.moduleBlock != nil {
		return fmt.Sprintf(
			"%s:%s",
			b.moduleBlock.FullName(),
			b.LocalName(),
		)
	}

	return b.LocalName()
}

func (b *HCLBlock) UniqueName() string {
	if b.moduleBlock != nil {
		return fmt.Sprintf("%s:%s:%s", b.FullName(), b.Range().Filename, b.moduleBlock.UniqueName())
	}
	return fmt.Sprintf("%s:%s", b.FullName(), b.Range().Filename)
}

func (b *HCLBlock) TypeLabel() string {
	if len(b.Labels()) > 0 {
		return b.Labels()[0]
	}
	return ""
}

func (b *HCLBlock) NameLabel() string {
	if len(b.Labels()) > 1 {
		return b.Labels()[1]
	}
	return ""
}

func (b *HCLBlock) HasChild(childElement string) bool {
	return b.GetAttribute(childElement).IsNotNil() || b.GetBlock(childElement).IsNotNil()
}

func (b *HCLBlock) MissingChild(childElement string) bool {
	if b == nil {
		return true
	}

	return !b.HasChild(childElement)
}

func (b *HCLBlock) InModule() bool {
	if b == nil {
		return false
	}
	return b.moduleBlock != nil
}

func (b *HCLBlock) Label() string {
	return strings.Join(b.hclBlock.Labels, ".")
}

func (b *HCLBlock) HasBlock(childElement string) bool {
	return b.GetBlock(childElement).IsNil()
}

func (b *HCLBlock) IsResourceType(resourceType string) bool {
	return b.TypeLabel() == resourceType
}

func (b *HCLBlock) IsEmpty() bool {
	return len(b.AllBlocks()) == 0 && len(b.GetAttributes()) == 0
}

func (b *HCLBlock) Attributes() map[string]Attribute {
	attributes := make(map[string]Attribute)
	for name, attr := range b.getHCLAttributes() {
		attributes[name] = NewHCLAttribute(attr, b.evalContext)
	}
	return attributes
}

func (b *HCLBlock) Values() cty.Value {

	values := make(map[string]cty.Value)
	for _, attribute := range b.getHCLAttributes() {
		func() {
			defer func() {
				if err := recover(); err != nil {
					return
				}
			}()
			val, _ := attribute.Expr.Value(b.evalContext)
			values[attribute.Name] = val
		}()
	}
	return cty.ObjectVal(values)
}

func (b *HCLBlock) IsNil() bool {
	return b == nil
}

func (b *HCLBlock) IsNotNil() bool {
	return !b.IsNil()
}
