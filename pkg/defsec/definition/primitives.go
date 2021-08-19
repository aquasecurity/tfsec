package definition

type BoolValue struct {
	*Metadata
	Value bool
}

type StringValue struct {
	*Metadata
	Value string
}

func (b *BoolValue) IsTrue() bool {
	return b.Value
}

func (b *BoolValue) IsFalse() bool {
	return !b.Value
}

func (s *StringValue) EqualTo(value string) bool {
	return s.Value == value
}

func (s *StringValue) NotEqualTo(value string) bool {
	return s.Value != value
}
