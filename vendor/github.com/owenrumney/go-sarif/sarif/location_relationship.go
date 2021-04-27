package sarif

type LocationRelationship struct {
	PropertyBag
	Target      uint     `json:"target"`
	Kinds       []string `json:"kinds,omitempty"`
	Description *Message `json:"description,omitempty"`
}

func NewLocationRelationship(target int) *LocationRelationship {
	t := uint(target)
	return &LocationRelationship{
		Target: t,
	}
}

func (l *LocationRelationship) WithKind(kind string) *LocationRelationship {
	l.Kinds = append(l.Kinds, kind)
	return l
}

func (l *LocationRelationship) WithDescription(message *Message) *LocationRelationship {
	l.Description = message
	return l
}
