package models

import "fmt"

type Result struct {
	Range       *Range
	Description string
}

type Range struct {
	Filename  string
	StartLine int
	EndLine   int
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
