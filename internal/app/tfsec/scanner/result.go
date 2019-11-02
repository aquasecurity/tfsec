package scanner

import (
	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// Result is a positive result for a security check. It encapsulates a code unique to the specific check it was raised
// by, a human-readable description and a range
type Result struct {
	Code            CheckCode
	Range           parser.Range
	Description     string
	RangeAnnotation string
}
