package models

// Result represents the results block in the sarif report
type Result struct {
	Level     string            `json:"level"`
	Message   *textBlock        `json:"message"`
	RuleId    string            `json:"ruleId"`
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
	Uri   string `json:"uri"`
	Index int    `json:"index"`
}

type l struct {
	Uri string `json:"uri"`
}

func newRuleResult(ruleId string) *Result {
	return &Result{
		RuleId: ruleId,
	}
}

func (result *Result) WithLevel(level string) *Result {
	result.Level = level
	return result
}

func (result *Result) WithMessage(message string) *Result {
	result.Message = &textBlock{
		Text: message,
	}
	return result
}

func (result *Result) WithLocationDetails(path string, startLine, startColumn int) *Result {
	location := &physicalLocation{
		ArtifactLocation: &artifactLocation{
			Uri: path,
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
