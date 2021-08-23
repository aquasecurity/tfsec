package definition

type BoolValue struct {
	*Metadata
	Value bool
}

func (b *BoolValue) IsTrue() bool {
	return b.Value
}

func (b *BoolValue) IsFalse() bool {
	return !b.Value
}
