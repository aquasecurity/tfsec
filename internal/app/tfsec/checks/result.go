package checks

import "github.com/liamg/tfsec/internal/app/tfsec/parser"

// Result is a positive result for a security check. It encapsulates a code unqie to the specific check it was raised
// by, a human-readable description and a range
type Result struct {
	Code        Code
	Range       parser.Range
	Description string
}

// NewResult creates a new Result, containing the given code, description and range
func NewResult(code Code, description string, r parser.Range) Result {
	return Result{
		Code:        code,
		Description: description,
		Range:       r,
	}
}
