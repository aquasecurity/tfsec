package definition

type Metadata struct {
	Range     Range
	IsDefined bool
	Reference string
}

func NewMetadata(r Range) *Metadata {
	return &Metadata{
		Range:     r,
		IsDefined: true,
	}
}

func (m *Metadata) WithReference(reference string) *Metadata {
	m.Reference = reference
	return m
}

type ValueType interface {
	// Contains(checkValue interface{}, equalityOptions ...EqualityOption) bool
	//NotContains(checkValue interface{}, equalityOptions ...EqualityOption) bool
	//StartsWith(prefix interface{}) bool
	//EndsWith(suffix interface{}) bool
	//Equals(checkValue interface{}, equalityOptions ...EqualityOption) bool
	//NotEqual(checkValue interface{}, equalityOptions ...EqualityOption) bool
	//RegexMatches(pattern interface{}) bool
	//IsAny(options ...interface{}) bool
	//IsNotAny(options ...interface{}) bool
	//IsNone(options ...interface{}) bool
	IsTrue() bool
	//IsFalse() bool
	//IsEmpty() bool
	//IsNotEmpty() bool
	//IsNil() bool
	//IsNotNil() bool
	//LessThan(checkValue interface{}) bool
	//LessThanOrEqualTo(checkValue interface{}) bool
	//GreaterThan(checkValue interface{}) bool
	//GreaterThanOrEqualTo(checkValue interface{}) bool
	//IsString() bool
	//IsNumber() bool
	// IsBool() bool
}
