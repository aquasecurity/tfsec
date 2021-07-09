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
	StartsWith(prefix interface{}) bool
	EndsWith(suffix interface{}) bool
	Equals(checkValue interface{}, equalityOptions ...EqualityOption) bool
	RegexMatches(pattern interface{}) bool
	IsAny(options ...interface{}) bool
	IsNone(options ...interface{}) bool
	IsTrue() bool
	IsFalse() bool
	IsEmpty() bool
	MapValue(mapKey string) cty.Value
	LessThan(checkValue interface{}) bool
	LessThanOrEqualTo(checkValue interface{}) bool
	GreaterThan(checkValue interface{}) bool
	GreaterThanOrEqualTo(checkValue interface{}) bool
	IsDataBlockReference() bool
	Reference() (*Reference, error)
	IsResourceBlockReference(resourceType string) bool
	ReferencesBlock(b Block) bool
	IsResolvable() bool
	IsString() bool
	IsNumber() bool
	IsBool() bool
	ValueAsStrings() []string
}
