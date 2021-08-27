package types

type BoolValue interface {
	metadataProvider
	Value() bool
	IsTrue() bool
	IsFalse() bool
}

type boolValue struct {
	metadata *Metadata
	value    bool
}

func Bool(value bool, metadata *Metadata) BoolValue {
	return &boolValue{
		value:    value,
		metadata: metadata,
	}
}

func BoolDefault(value bool, metadata *Metadata) BoolValue {
	b := Bool(value, metadata)
	b.Metadata().isDefault = true
	return b
}

func BoolExplicit(value bool, metadata *Metadata) BoolValue {
	b := Bool(value, metadata)
	b.Metadata().isExplicit = true
	return b
}

func (b *boolValue) Metadata() *Metadata {
	return b.metadata
}

func (b *boolValue) Value() bool {
	return b.value
}

func (b *boolValue) IsTrue() bool {
	return b.Value()
}

func (b *boolValue) IsFalse() bool {
	return !b.Value()
}
