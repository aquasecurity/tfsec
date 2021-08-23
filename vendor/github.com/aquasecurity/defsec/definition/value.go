package definition

type Metadata struct {
	Range     Range
	Reference Reference
}

func NewMetadata(r Range) *Metadata {
	return &Metadata{
		Range: r,
	}
}

func (m *Metadata) WithReference(reference Reference) *Metadata {
	m.Reference = reference
	return m
}
