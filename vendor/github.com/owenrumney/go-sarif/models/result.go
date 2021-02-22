package models

// Result represents the results block in the sarif report
type Result struct {
	Level     string            `json:"level"`
	Message   *textBlock        `json:"message"`
	RuleID    string            `json:"ruleId"`
	RuleIndex int               `json:"ruleIndex"`
	Locations []*resultLocation `json:"locations,omitempty"`
}

type resultLocation struct {
	PhysicalLocation *physicalLocation `json:"physicalLocation,omitempty"`
}

type physicalLocation struct {
	ArtifactLocation *artifactLocation `json:"artifactLocation"`
	Region           *region           `json:"region"`
}

type region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

type artifactLocation struct {
	URI   string `json:"uri"`
	Index int    `json:"index"`
}

type location struct {
	URI string `json:"uri"`
}

func newRuleResult(ruleID string) *Result {
	return &Result{
		RuleID: ruleID,
	}
}

// WithLevel specifies the level of the finding, error, warning for a result and returns the updated result
func (result *Result) WithLevel(level string) *Result {
	result.Level = level
	return result
}

// WithMessage specifies the message for a result and returns the updated result
func (result *Result) WithMessage(message string) *Result {
	result.Message = &textBlock{
		Text: message,
	}
	return result
}

// WithLocationDetails specifies the location details of the Result and returns the update result
func (result *Result) WithLocationDetails(path string, startLine, startColumn int) *Result {
	location := &physicalLocation{
		ArtifactLocation: &artifactLocation{
			URI: path,
		},
		Region: &region{
			StartLine:   startLine,
			StartColumn: startColumn,
		},
	}
	result.Locations = append(result.Locations, &resultLocation{
		PhysicalLocation: location,
	})
	return result
}
