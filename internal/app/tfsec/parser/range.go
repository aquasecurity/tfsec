package parser

import "fmt"

// Range describes an area of code, including the filename it is present in and the lin numbers the code occupies
type Range struct {
	Filename  string
	StartLine int
	EndLine   int
}

// String creates a human-readable summary of the range
func (r *Range) String() string {
	if r == nil {
		return "unknown"
	}
	if r.StartLine != r.EndLine {
		return fmt.Sprintf("%s:%d-%d", r.Filename, r.StartLine, r.EndLine)
	}
	return fmt.Sprintf("%s:%d", r.Filename, r.StartLine)
}
