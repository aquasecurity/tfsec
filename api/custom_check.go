package api

type MatchType int
type CheckAction int
type Severity string
type Provider string

const (
	Block MatchType = iota
	Attribute

	AWS     Provider = "aws"
	GCP     Provider = "google"
	Azure   Provider = "azure"
	General Provider = "*"

	IsPresent CheckAction = iota
	IsNotPresent
	StartsWith
	EndsWith
	Contains

	SeverityError   Severity = "ERROR"
	SeverityWarning Severity = "WARNING"
	SeverityInfo    Severity = "INFO"
)

type Matcher struct {
	MatchName   string
	MatchValue  string
	CheckAction CheckAction
	Type        MatchType
	SubMatcher  *Matcher
}

type CustomCheck struct {
	Code           string
	Description    string
	Provider       Provider
	RequiredTypes  []string
	RequiredLabels []string
	Matcher        *Matcher
	Severity       Severity
}
