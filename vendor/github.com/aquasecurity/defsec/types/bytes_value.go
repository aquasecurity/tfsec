package types

type BytesValue interface {
	metadataProvider
	Value() []byte
	Len() int
}

type bytesValue struct {
	metadata *Metadata
	value    []byte
}

func (b *bytesValue) Value() []byte {
	return b.value
}

func (b *bytesValue) Len() int {
	return len(b.value)
}

func (b *bytesValue) Metadata() *Metadata {
	return b.metadata
}

func Bytes(value []byte, r Range, ref Reference) BytesValue {
	return &bytesValue{
		value:    value,
		metadata: NewMetadata(r, ref),
	}
}

func BytesDefault(value []byte, r Range, ref Reference) BytesValue {
	b := Bytes(value, r, ref)
	b.Metadata().isDefault = true
	return b
}

func BytesExplicit(value []byte, r Range, ref Reference) BytesValue {
	b := Bytes(value, r, ref)
	b.Metadata().isExplicit = true
	return b
}
