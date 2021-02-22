package models

// Run type represents a run of a tool
type Run struct {
	Tool      *tool              `json:"tool"`
	Artifacts []*LocationWrapper `json:"artifacts,omitempty"`
	Results   []*Result          `json:"results,omitempty"`
}

// LocationWrapper reprents the location details of a run
type LocationWrapper struct {
	Location *location `json:"location,omitempty"`
}

// NewRun allows the creation of a new Run
func NewRun(toolName, informationURI string) *Run {
	tool := &tool{
		Driver: &driver{
			Name:           toolName,
			InformationURI: informationURI,
		},
	}
	run := &Run{
		Tool: tool,
	}
	return run
}

// AddArtifact returns the index of an existing artefact, the newly added artifactLocation
func (run *Run) AddArtifact(artifactLocation string) int {
	for i, l := range run.Artifacts {
		if l.Location.URI == artifactLocation {
			return i
		}
	}
	run.Artifacts = append(run.Artifacts, &LocationWrapper{
		Location: &location{
			URI: artifactLocation,
		},
	})
	return len(run.Artifacts) - 1
}

// AddRule returns an existing Rule for the ruleID or creates a new Rule and returns it
func (run *Run) AddRule(ruleID string) *Rule {
	for _, rule := range run.Tool.Driver.Rules {
		if rule.ID == ruleID {
			return rule
		}
	}
	rule := newRule(ruleID)
	run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
	return rule
}

// AddResult returns an existing Result or creates a new one and returns it
func (run *Run) AddResult(ruleID string) *Result {
	for _, result := range run.Results {
		if result.RuleID == ruleID {
			return result
		}
	}
	result := newRuleResult(ruleID)
	run.Results = append(run.Results, result)
	return result
}

// AddResultDetails adds rules to the driver and artifact locations if they are missing. It adds the result to the result block as well
func (run *Run) AddResultDetails(rule *Rule, result *Result, location string) {
	ruleIndex := run.Tool.Driver.getOrCreateRule(rule)
	result.RuleIndex = ruleIndex
	locationIndex := run.AddArtifact(location)
	updateResultLocationIndex(result, location, locationIndex)
}

func updateResultLocationIndex(result *Result, location string, index int) {
	for _, resultLocation := range result.Locations {
		if resultLocation.PhysicalLocation.ArtifactLocation.URI == location {
			resultLocation.PhysicalLocation.ArtifactLocation.Index = index
			break
		}
	}
}
