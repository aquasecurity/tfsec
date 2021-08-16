package block

import (
	"github.com/zclconf/go-cty/cty"
)

type Attribute interface {
	IsLiteral() bool
	Type() cty.Type
	Value() cty.Value
	Range() Range
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
	Reference() (*Reference, error)
	AllReferences() []*Reference
	IsResourceBlockReference(resourceType string) bool
	ReferencesBlock(b Block) bool
	IsResolvable() bool
	IsNotResolvable() bool
	IsString() bool
	IsNumber() bool
	IsBool() bool
	ValueAsStrings() []string
	IsIterable() bool
	Each(f func(key cty.Value, val cty.Value))
}
