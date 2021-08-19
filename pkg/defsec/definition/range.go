package definition

type Range interface {
	GetFilename() string
	GetStartLine() int
	GetEndLine() int
	Overlaps(a Range) bool
	String() string
}
