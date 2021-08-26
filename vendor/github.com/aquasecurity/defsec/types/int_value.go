package types

type IntValue interface {
	metadataProvider
	Value() int
}

type intValue struct {
	metadata *Metadata
	value    int
}

func Int(value int, m *Metadata) IntValue {
	return &intValue{
		value:    value,
		metadata: m,
	}
}

func IntDefault(value int, m *Metadata) IntValue {
	b := Int(value, m)
	b.Metadata().isDefault = true
	return b
}

func IntExplicit(value int, m *Metadata) IntValue {
	b := Int(value, m)
	b.Metadata().isExplicit = true
	return b
}

func (b *intValue) Metadata() *Metadata {
	return b.metadata
}

func (b *intValue) Value() int {
	return b.value
}
