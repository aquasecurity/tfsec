package types

type MapValue interface {
	metadataProvider
	Value() map[string]string
	HasKey(key string) bool
	Len() int
}

type mapValue struct {
	metadata *Metadata
	value    map[string]string
}

func Map(value map[string]string, m *Metadata) MapValue {
	return &mapValue{
		value:    value,
		metadata: m,
	}
}

func MapDefault(value map[string]string, m *Metadata) MapValue {
	b := Map(value, m)
	b.GetMetadata().isDefault = true
	return b
}

func MapExplicit(value map[string]string, m *Metadata) MapValue {
	b := Map(value, m)
	b.GetMetadata().isExplicit = true
	return b
}

func (b *mapValue) GetMetadata() *Metadata {
	return b.metadata
}

func (b *mapValue) Value() map[string]string {
	return b.value
}

func (b *mapValue) GetRawValue() interface{} {
	return b.value
}

func (b *mapValue) Len() int {
	return len(b.value)
}

func (b *mapValue) HasKey(key string) bool {
	if b.value == nil {
		return false
	}
	_, ok := b.value[key]
	return ok
}
