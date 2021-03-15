package scanner

import (
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// Result is a positive result for a security check. It encapsulates a code unique to the specific check it was raised
// by, a human-readable description and a range
type Result struct {
	RuleID          RuleCode     `json:"rule_id"`
	RuleDescription RuleSummary  `json:"rule_description"`
	RuleProvider    RuleProvider `json:"rule_provider"`
	Link            string       `json:"link"`
	Range           parser.Range `json:"location"`
	Description     string       `json:"description"`
	RangeAnnotation string       `json:"-"`
	Severity        Severity     `json:"severity"`
	Passed          bool         `json:"passed"`
}

type Severity string

const (
	SeverityError   Severity = "ERROR"
	SeverityWarning Severity = "WARNING"
	SeverityInfo    Severity = "INFO"
)

var ValidSeverity = []Severity{
	SeverityError, SeverityWarning, SeverityInfo,
}

func (r *Result) OverrideSeverity(severity string) {
	r.Severity = Severity(severity)
}

func (s *Severity) IsValid() bool {
	for _, severity := range ValidSeverity {
		if severity == *s {
			return true
		}
	}
	return false
}

func (s *Severity) Valid() []Severity {
	return ValidSeverity
}
