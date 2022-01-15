package types

type Reference interface {
	String() string
	LogicalID() string
	RefersTo(r Reference) bool
}

type FakeReference struct {
}

func (f *FakeReference) String() string {
	return "something"
}

func (f *FakeReference) RefersTo(r Reference) bool {
	return false
}

func (f *FakeReference) LogicalID() string {
	return "something"
}
