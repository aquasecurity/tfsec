package scanner

import (
	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// Result is a positive result for a security check. It encapsulates a code unique to the specific check it was raised
// by, a human-readable description and a range
type Result struct {
	Code            CheckCode    `json:"code"`
	Range           parser.Range `json:"location"`
	Description     string       `json:"description"`
	RangeAnnotation string       `json:"-"`
}
