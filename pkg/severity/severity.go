package severity

type Severity string

const (
	None     Severity = ""
	Critical Severity = "CRITICAL"
	Error    Severity = "ERROR"
	Warning  Severity = "WARNING"
	Info     Severity = "INFO"
)

var ValidSeverity = []Severity{
	Critical, Error, Warning, Info,
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
