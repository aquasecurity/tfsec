package sarif

type LogicalLocation struct { // https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Ref493404505
	PropertyBag
	Index              *uint   `json:"index,omitempty"`
	Name               *string `json:"name,omitempty"`
	FullyQualifiedName *string `json:"fullyQualifiedName,omitempty"`
	DecoratedName      *string `json:"decoratedName,omitempty"`
	Kind               *string `json:"kind,omitempty"`
	ParentIndex        *uint   `json:"parentIndex,omitempty"`
}

func NewLogicalLocation() *LogicalLocation {
	return &LogicalLocation{}
}

func (l *LogicalLocation) WithIndex(index int) *LogicalLocation {
	i := uint(index)
	l.Index = &i
	return l
}

func (l *LogicalLocation) WithName(name string) *LogicalLocation {
	l.Name = &name
	return l
}

func (l *LogicalLocation) WithFullyQualifiedName(fullyQualifiedName string) *LogicalLocation {
	l.FullyQualifiedName = &fullyQualifiedName
	return l
}

func (l *LogicalLocation) WithDecoratedName(decoratedName string) *LogicalLocation {
	l.DecoratedName = &decoratedName
	return l
}

func (l *LogicalLocation) WithKind(kind string) *LogicalLocation {
	l.Kind = &kind
	return l
}

func (l *LogicalLocation) WithParentIndex(parentIndex int) *LogicalLocation {
	i := uint(parentIndex)
	l.ParentIndex = &i
	return l
}
