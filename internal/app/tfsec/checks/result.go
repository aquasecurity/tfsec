package checks

import "fmt"

// Result is a positive result for a security check. It encapsulates a code unqie to the specific check it was raised
// by, a human-readable description and a range
type Result struct {
	Code        Code
	Range       *Range
	Description string
}

// NewResult creates a new Result, containing the given code, description and range
func NewResult(code Code, description string, r *Range) Result {
	return Result{
		Code:        code,
		Description: description,
		Range:       r,
	}
}

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
