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

func (b *bytesValue) GetRawValue() interface{} {
	return b.value
}

func (b *bytesValue) Len() int {
	return len(b.value)
}

func (b *bytesValue) GetMetadata() *Metadata {
	return b.metadata
}

func Bytes(value []byte, m *Metadata) BytesValue {
	return &bytesValue{
		value:    value,
		metadata: m,
	}
}

func BytesDefault(value []byte, m *Metadata) BytesValue {
	b := Bytes(value, m)
	b.GetMetadata().isDefault = true
	return b
}

func BytesExplicit(value []byte, m *Metadata) BytesValue {
	b := Bytes(value, m)
	b.GetMetadata().isExplicit = true
	return b
}
