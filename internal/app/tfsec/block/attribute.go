package block

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/types"
	"github.com/zclconf/go-cty/cty"
)

type Attribute interface {
	rules.MetadataProvider
	IsLiteral() bool
	Type() cty.Type
	Value() cty.Value
	Range() HCLRange
	Name() string
	Contains(checkValue interface{}, equalityOptions ...EqualityOption) bool
	NotContains(checkValue interface{}, equalityOptions ...EqualityOption) bool
	HasIntersect(checkValues ...interface{}) bool
	StartsWith(prefix interface{}) bool
	EndsWith(suffix interface{}) bool
	Equals(checkValue interface{}, equalityOptions ...EqualityOption) bool
	NotEqual(checkValue interface{}, equalityOptions ...EqualityOption) bool
	RegexMatches(pattern interface{}) bool
	IsAny(options ...interface{}) bool
	IsNotAny(options ...interface{}) bool
	IsNone(options ...interface{}) bool
	IsTrue() bool
	IsFalse() bool
	IsEmpty() bool
	IsNotEmpty() bool
	IsNil() bool
	IsNotNil() bool
	MapValue(mapKey string) cty.Value
	LessThan(checkValue interface{}) bool
	LessThanOrEqualTo(checkValue interface{}) bool
	GreaterThan(checkValue interface{}) bool
	GreaterThanOrEqualTo(checkValue interface{}) bool
	IsDataBlockReference() bool
	Reference() *Reference
	SingleReference() (*Reference, error)
	AllReferences(blocks ...Block) []*Reference
	IsResourceBlockReference(resourceType string) bool
	References(r types.Reference) bool
	IsResolvable() bool
	IsNotResolvable() bool
	IsString() bool
	IsNumber() bool
	IsBool() bool
	ValueAsStrings() []string
	IsIterable() bool
	Each(f func(key cty.Value, val cty.Value))
	AsStringValueOrDefault(defaultValue string, parent Block) types.StringValue
	AsBoolValueOrDefault(defaultValue bool, parent Block) types.BoolValue
	AsIntValueOrDefault(defaultValue int, parent Block) types.IntValue
	Metadata() types.Metadata
	ReferencesBlock(b Block) bool
}
