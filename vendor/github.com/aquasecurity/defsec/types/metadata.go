package types

type metadataProvider interface {
	GetMetadata() *Metadata
	GetRawValue() interface{}
}

type Metadata struct {
	rnge           Range
	ref            Reference
	isManaged      bool
	isDefault      bool
	isExplicit     bool
	isUnresolvable bool
}

func NewMetadata(r Range, ref Reference) Metadata {
	if r == nil {
		panic("range is nil")
	}
	if ref == nil {
		panic("reference is nil")
	}
	return Metadata{
		rnge:      r,
		ref:       ref,
		isManaged: true,
	}
}

func NewUnmanagedMetadata(r Range, ref Reference) Metadata {
	m := NewMetadata(r, ref)
	m.isManaged = false
	return m
}

func (m *Metadata) IsDefault() bool {
	return m.isDefault
}

func (m *Metadata) IsExplicit() bool {
	return m.isExplicit
}

func (m *Metadata) String() string {
	return m.ref.String()
}

func (m *Metadata) Reference() Reference {
	return m.ref
}

func (m *Metadata) Range() Range {
	if m == nil {
		panic("metadata is nil")
	}
	return m.rnge
}

func (m *Metadata) IsManaged() bool {
	if m == nil {
		panic("metadata is nil")
	}
	return m.isManaged
}
