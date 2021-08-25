package types

type IntValue interface {
	metadataProvider
	Value() int
}

type intValue struct {
	metadata *Metadata
	value    int
}

func Int(value int, r Range, ref Reference) IntValue {
	return &intValue{
		value:    value,
		metadata: NewMetadata(r, ref),
	}
}

func IntDefault(value int, r Range, ref Reference) IntValue {
	b := Int(value, r, ref)
	b.Metadata().isDefault = true
	return b
}

func IntExplicit(value int, r Range, ref Reference) IntValue {
	b := Int(value, r, ref)
	b.Metadata().isExplicit = true
	return b
}

func (b *intValue) Metadata() *Metadata {
	return b.metadata
}

func (b *intValue) Value() int {
	return b.value
}
