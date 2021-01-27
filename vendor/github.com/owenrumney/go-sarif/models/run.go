package models

type Run struct {
	Tool      *tool              `json:"tool"`
	Artifacts []*LocationWrapper `json:"artifacts,omitempty"`
	Results   []*Result          `json:"results,omitempty"`
}

type LocationWrapper struct {
	Location *l `json:"location,omitentry"`
}

func NewRun(toolName, informationUri string) *Run {
	tool := &tool{
		Driver: &driver{
			Name:           toolName,
			InformationUri: informationUri,
		},
	}
	run := &Run{
		Tool: tool,
	}
	return run
}

// AddArtifact returns the index of the newly added artifactLocation
func (run *Run) AddArtifact(location string) int {
	for i, l := range run.Artifacts {
		if l.Location.Uri == location {
			return i
		}
	}
	run.Artifacts = append(run.Artifacts, &LocationWrapper{
		Location: &l{
			Uri: location,
		},
	})
	return len(run.Artifacts) - 1
}

func (run *Run) AddRule(ruleId string) *rule {
	for _, rule := range run.Tool.Driver.Rules {
		if rule.Id == ruleId {
			return rule
		}
	}
	rule := newRule(ruleId)
	run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
	return rule
}

func (run *Run) AddResult(ruleId string) *Result {
	for _, result := range run.Results {
		if result.RuleId == ruleId {
			return result
		}
	}
	result := newRuleResult(ruleId)
	run.Results = append(run.Results, result)
	return result
}

// AddResultDetails adds rules to the driver and artifact locations if they are missing. It adds the result to the result block as well
func (run *Run) AddResultDetails(rule *rule, result *Result, location string) {
	ruleIndex := run.Tool.Driver.getOrCreateRule(rule)
	result.RuleIndex = ruleIndex
	locationIndex := run.AddArtifact(location)
	updateResultLocationIndex(result, location, locationIndex)
}

func updateResultLocationIndex(result *Result, location string, index int) {
	for _, resultLocation := range result.Locations {
		if resultLocation.PhysicalLocation.ArtifactLocation.Uri == location {
			resultLocation.PhysicalLocation.ArtifactLocation.Index = index
			break
		}
	}
}
