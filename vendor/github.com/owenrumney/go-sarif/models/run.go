package models

import (
	"fmt"
)

// Run type represents a run of a tool
type Run struct { // https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10540922
	Tool      tool        `json:"tool"`
	Artifacts []*artifact `json:"artifacts,omitempty"`
	Results   []*Result   `json:"results,omitempty"` //	can	be	null
}



// NewRun allows the creation of a new Run
func NewRun(toolName, informationURI string) *Run {
	run := &Run{
		Tool: tool{
			Driver: &driver{
				Name:           toolName,
				InformationURI: informationURI,
			},
		},
	}
	return run
}

// AddArtifact returns the index of an existing artefact, the newly added artifactLocation
func (run *Run) AddArtifact(uri string) uint {
	for i, l := range run.Artifacts {
		if *l.Location.URI == uri {
			return uint(i)
		}
	}
	run.Artifacts = append(run.Artifacts, &artifact{
		Location: &artifactLocation{
			URI: &uri,
		},
	})
	return uint(len(run.Artifacts) - 1)
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
		if *result.RuleID == ruleID {
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
	result.RuleIndex = &ruleIndex
	locationIndex := run.AddArtifact(location)
	updateResultLocationIndex(result, location, locationIndex)
}

func updateResultLocationIndex(result *Result, location string, index uint) {
	for _, resultLocation := range result.Locations {
		if *resultLocation.PhysicalLocation.ArtifactLocation.URI == location {
			resultLocation.PhysicalLocation.ArtifactLocation.Index = &index
			break
		}
	}
}

func (run *Run) GetRuleById(ruleId string) (*Rule, error) {
	if run.Tool.Driver != nil {
		for _, rule := range run.Tool.Driver.Rules {
			if rule.ID == ruleId {
				return rule, nil
			}
		}
	}

	return nil, fmt.Errorf("couldn't find rule %s", ruleId)
}
