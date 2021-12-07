package sarif

type Address struct { // https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10541049
	PropertyBag
	Index              *uint   `json:"index,omitempty"`
	AbsoluteAddress    *uint   `json:"absoluteAddress,omitempty"`
	RelativeAddress    *int    `json:"relativeAddress,omitempty"`
	OffsetFromParent   *int    `json:"offsetFromParent,omitempty"`
	Length             *int    `json:"length,omitempty"`
	Name               *string `json:"name,omitempty"`
	FullyQualifiedName *string `json:"fullyQualifiedName,omitempty"`
	Kind               *string `json:"kind,omitempty"`
	ParentIndex        *uint   `json:"parentIndex,omitempty"`
}

func NewAddress() *Address {
	return &Address{}
}

func (a *Address) WithIndex(index int) *Address {
	i := uint(index)
	a.Index = &i
	return a
}

func (a *Address) WithAbsoluteAddress(absoluteAddress int) *Address {
	i := uint(absoluteAddress)
	a.AbsoluteAddress = &i
	return a
}

func (a *Address) WithRelativeAddress(relativeAddress int) *Address {
	a.RelativeAddress = &relativeAddress
	return a
}

func (a *Address) WithOffsetFromParent(offsetFromParent int) *Address {
	a.OffsetFromParent = &offsetFromParent
	return a
}

func (a *Address) WithLength(length int) *Address {
	a.Length = &length
	return a
}

func (a *Address) WithName(name string) *Address {
	a.Name = &name
	return a
}

func (a *Address) WithFullyQualifiedName(fullyQualifiedName string) *Address {
	a.FullyQualifiedName = &fullyQualifiedName
	return a
}

func (a *Address) WithKind(kind string) *Address {
	a.Kind = &kind
	return a
}

func (a *Address) WithParentIndex(parentIndex int) *Address {
	i := uint(parentIndex)
	a.ParentIndex = &i
	return a
}
