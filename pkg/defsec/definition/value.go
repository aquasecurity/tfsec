package definition

type Metadata struct {
	Range     Range
	IsDefined bool
	Reference string
}

func NewMetadata(r Range) Metadata {
	return Metadata{
		Range:     r,
		IsDefined: true,
	}
}
