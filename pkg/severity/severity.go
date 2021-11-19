package severity

import (
	"strings"
)

type Severity string

const (
	None     Severity = ""
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
)

var ValidSeverity = []Severity{
	Critical, High, Medium, Low,
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

func (s Severity) AsOrdinal() int {
	switch s {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	default:
		return 0
	}
}

func StringToSeverity(sev string) Severity {
	s := strings.ToUpper(sev)
	switch s {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return Severity(s)
	case "ERROR":
		return High
	case "WARNING":
		return Medium
	case "INFO":
		return Low
	default:
		return None
	}
}
