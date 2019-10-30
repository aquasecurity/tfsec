package checks

import "fmt"

type Result struct {
	Code        Code
	Range       *Range
	Description string
}

func NewResult(code Code, description string, r *Range) Result {
	return Result{
		Code:        code,
		Description: description,
		Range:       r,
	}
}

type Range struct {
	Filename    string
	StartLine   int
	EndLine     int
	NonSpecific bool
}

func (r *Range) String() string {
	if r == nil {
		return "unknown"
	}
	if r.StartLine != r.EndLine {
		return fmt.Sprintf("%s:%d-%d", r.Filename, r.StartLine, r.EndLine)
	}
	return fmt.Sprintf("%s:%d", r.Filename, r.StartLine)
}
