package definition

type Range interface {
	GetFilename() string
	GetModule() string
	GetStartLine() int
	GetEndLine() int
	Overlaps(a Range) bool
	String() string
}
