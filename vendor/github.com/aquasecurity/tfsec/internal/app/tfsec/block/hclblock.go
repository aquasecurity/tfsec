package block

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/schema"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
)

type HCLBlock struct {
	hclBlock    *hcl.Block
	context     *Context
	moduleBlock Block
	expanded    bool
	cloneIndex  int
	childBlocks []Block
	attributes  []Attribute
}

func NewHCLBlock(hclBlock *hcl.Block, ctx *Context, moduleBlock Block) Block {
	if ctx == nil {
		ctx = NewContext(&hcl.EvalContext{}, nil)
	}

	var children Blocks
	switch body := hclBlock.Body.(type) {
	case *hclsyntax.Body:
		for _, b := range body.Blocks {
			children = append(children, NewHCLBlock(b.AsHCLBlock(), ctx, moduleBlock))
		}
	default:
		content, _, diag := hclBlock.Body.PartialContent(schema.TerraformSchema_0_12)
		if diag == nil {
			for _, hb := range content.Blocks {
				children = append(children, NewHCLBlock(hb, ctx, moduleBlock))
			}
		}
	}

	b := HCLBlock{
		context:     ctx,
		hclBlock:    hclBlock,
		moduleBlock: moduleBlock,
		childBlocks: children,
	}

	module := b.Range().module
	for _, attr := range b.createAttributes() {
		b.attributes = append(b.attributes, NewHCLAttribute(attr, ctx, module, b.Reference()))
	}

	return &b
}

func (b *HCLBlock) Metadata() types.Metadata {
	return types.NewMetadata(b.Range(), b.Reference())
}

func (b *HCLBlock) GetMetadata() *types.Metadata {
	m := b.Metadata()
	return &m
}

func (b *HCLBlock) GetRawValue() interface{} {
	return nil
}

func (b *HCLBlock) InjectBlock(block Block, name string) {
	block.(*HCLBlock).hclBlock.Labels = []string{}
	block.(*HCLBlock).hclBlock.Type = name
	for attrName, attr := range block.Attributes() {
		b.context.Root().SetByDot(attr.Value(), fmt.Sprintf("%s.%s.%s", b.Reference().String(), name, attrName))
	}
	b.childBlocks = append(b.childBlocks, block)
}

func (b *HCLBlock) markCountExpanded() {
	b.expanded = true
}

func (b *HCLBlock) IsCountExpanded() bool {
	return b.expanded
}

func (b *HCLBlock) Clone(index cty.Value) Block {
	var childCtx *Context
	if b.context != nil {
		childCtx = b.context.NewChild()
	} else {
		childCtx = NewContext(&hcl.EvalContext{}, nil)
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
	clone.context.SetByDot(indexVal, "count.index")
	clone.markCountExpanded()
	b.cloneIndex++
	return clone
}

func (b *HCLBlock) Context() *Context {
	return b.context
}

func (b *HCLBlock) OverrideContext(ctx *Context) {
	b.context = ctx
	for _, block := range b.childBlocks {
		block.OverrideContext(ctx.NewChild())
	}
	for _, attr := range b.attributes {
		attr.(*HCLAttribute).ctx = ctx
	}
}

func (b *HCLBlock) Type() string {
	return b.hclBlock.Type
}

func (b *HCLBlock) Labels() []string {
	return b.hclBlock.Labels
}

func (b *HCLBlock) Range() HCLRange {
	if b == nil || b.hclBlock == nil {
		return HCLRange{}
	}
	var r hcl.Range
	switch body := b.hclBlock.Body.(type) {
	case *hclsyntax.Body:
		r = body.SrcRange
	default:
		r = b.hclBlock.DefRange
		r.End = b.hclBlock.Body.MissingItemRange().End
	}
	moduleName := "root"
	if b.moduleBlock != nil {
		moduleName = b.moduleBlock.FullName()
	}
	return NewRange(
		r.Filename,
		r.Start.Line,
		r.End.Line,
		moduleName,
	)
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

func (b *HCLBlock) createAttributes() hcl.Attributes {
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
	for _, child := range b.childBlocks {
		if child.Type() == name {
			return child
		}
	}
	return returnBlock
}

func (b *HCLBlock) AllBlocks() Blocks {
	if b == nil || b.hclBlock == nil {
		return nil
	}
	return b.childBlocks
}

func (b *HCLBlock) GetBlocks(name string) Blocks {
	if b == nil || b.hclBlock == nil {
		return nil
	}
	var results []Block
	for _, child := range b.childBlocks {
		if child.Type() == name {
			results = append(results, child)
		}
	}
	return results
}

func (b *HCLBlock) GetAttributes() []Attribute {
	if b == nil {
		return nil
	}
	return b.attributes
}

func (b *HCLBlock) GetAttribute(name string) Attribute {
	var attr *HCLAttribute
	if b == nil || b.hclBlock == nil {
		return attr
	}
	for _, attr := range b.attributes {
		if attr.Name() == name {
			return attr
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
	var parent string
	if b.moduleBlock != nil {
		parent = b.moduleBlock.FullName()
	}
	ref, _ := newReference(parts, parent)
	return ref
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
		return fmt.Sprintf("%s:%s:%s", b.FullName(), b.Range().GetFilename(), b.moduleBlock.UniqueName())
	}
	return fmt.Sprintf("%s:%s", b.FullName(), b.Range().GetFilename())
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

func (b *HCLBlock) MissingNestedChild(name string) bool {
	if b == nil {
		return true
	}

	parts := strings.Split(name, ".")
	blocks := parts[:len(parts)-1]
	last := parts[len(parts)-1]

	var working Block = b
	for _, subBlock := range blocks {
		if checkBlock := working.GetBlock(subBlock); checkBlock == nil {
			return true
		} else {
			working = checkBlock
		}
	}
	return !working.HasChild(last)

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
	for _, attr := range b.GetAttributes() {
		attributes[attr.Name()] = attr
	}
	return attributes
}

func (b *HCLBlock) Values() cty.Value {
	values := make(map[string]cty.Value)
	for _, attribute := range b.GetAttributes() {
		values[attribute.Name()] = attribute.Value()
	}
	return cty.ObjectVal(values)
}

func (b *HCLBlock) IsNil() bool {
	return b == nil
}

func (b *HCLBlock) IsNotNil() bool {
	return !b.IsNil()
}
