package types

type IntValue interface {
	metadataProvider
	Value() int
	EqualTo(i int) bool
	NotEqualTo(i int) bool
	LessThan(i int) bool
	GreaterThan(i int) bool
}

type intValue struct {
	metadata Metadata
	value    int
}

func Int(value int, m Metadata) IntValue {
	return &intValue{
		value:    value,
		metadata: m,
	}
}

func IntDefault(value int, m Metadata) IntValue {
	b := Int(value, m)
	b.GetMetadata().isDefault = true
	return b
}

func IntExplicit(value int, m Metadata) IntValue {
	b := Int(value, m)
	b.GetMetadata().isExplicit = true
	return b
}

func (b *intValue) GetMetadata() *Metadata {
	return &b.metadata
}

func (b *intValue) Value() int {
	return b.value
}

func (b *intValue) GetRawValue() interface{} {
	return b.value
}

func (b *intValue) NotEqualTo(i int) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return b.value != i
}

func (b *intValue) EqualTo(i int) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return b.value == i
}

func (b *intValue) LessThan(i int) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return b.value < i
}

func (b *intValue) GreaterThan(i int) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	return b.value > i
}
