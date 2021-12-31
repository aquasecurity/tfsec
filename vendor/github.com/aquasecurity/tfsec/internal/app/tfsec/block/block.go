package block

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/types"
	"github.com/zclconf/go-cty/cty"
)

type Block interface {
	rules.MetadataProvider
	Attributes() map[string]Attribute
	OverrideContext(ctx *Context)
	Type() string
	Labels() []string
	Range() HCLRange
	GetFirstMatchingBlock(names ...string) Block
	GetBlock(name string) Block
	AllBlocks() Blocks
	GetBlocks(name string) Blocks
	GetAttributes() []Attribute
	GetAttribute(name string) Attribute
	GetNestedAttribute(name string) Attribute
	Reference() *Reference
	LocalName() string
	FullName() string
	UniqueName() string
	TypeLabel() string
	NameLabel() string
	Clone(index cty.Value) Block
	IsCountExpanded() bool
	HasChild(childElement string) bool
	MissingChild(childElement string) bool
	MissingNestedChild(childElement string) bool
	InModule() bool
	Label() string
	HasBlock(childElement string) bool
	IsResourceType(resourceType string) bool
	IsEmpty() bool
	Values() cty.Value
	Context() *Context
	IsNil() bool
	IsNotNil() bool
	InjectBlock(block Block, name string)
	Metadata() types.Metadata
}
