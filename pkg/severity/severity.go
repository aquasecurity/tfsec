package severity

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
