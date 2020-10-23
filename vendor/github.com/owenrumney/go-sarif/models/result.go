package models

// Result represents the results block in the sarif report
type Result struct {
	Level     string            `json:"level"`
	Message   *TextBlock        `json:"message"`
	RuleId    string            `json:"ruleId"`
	RuleIndex int               `json:"ruleIndex"`
	Locations []*ResultLocation `json:"locations,omitempty"`
}

type ResultLocation struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
}

type PhysicalLocation struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation"`
	Region           *Region           `json:"region"`
}

type Region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

type ArtifactLocation struct {
	Uri   string `json:"uri"`
	Index int    `json:"index"`
}

type Location struct {
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
	result.Message = &TextBlock{
		Text: message,
	}
	return result
}

func (result *Result) WithLocationDetails(path string, startLine, startColumn int) *Result {
	location := &PhysicalLocation{
		ArtifactLocation: &ArtifactLocation{
			Uri: path,
		},
		Region: &Region{
			StartLine:   startLine,
			StartColumn: startColumn,
		},
	}
	result.Locations = append(result.Locations, &ResultLocation{
		PhysicalLocation: location,
	})
	return result
}
