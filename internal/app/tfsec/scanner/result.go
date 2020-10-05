package scanner

import (
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// Result is a positive result for a security check. It encapsulates a code unique to the specific check it was raised
// by, a human-readable description and a range
type Result struct {
	RuleID          RuleID       `json:"rule_id"`
	Link            string       `json:"link"`
	Range           parser.Range `json:"location"`
	Description     string       `json:"description"`
	RangeAnnotation string       `json:"-"`
	Severity        Severity     `json:"severity"`
}

type Severity string

const (
	SeverityError   Severity = "ERROR"
	SeverityWarning Severity = "WARNING"
	SeverityInfo    Severity = "INFO"
)
