package definition

type Reference interface {
	String() string
	RefersTo(r Reference) bool
}
