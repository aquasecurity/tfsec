package sarif

import (
	"fmt"
)

// Run type represents a run of a tool
type Run struct { // https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10540922
	Tool      Tool        `json:"tool"`
	Artifacts []*Artifact `json:"artifacts,omitempty"`
	Results   []*Result   `json:"results,omitempty"` //	can	be	null
}

// NewRun allows the creation of a new Run
func NewRun(toolName, informationURI string) *Run {
	run := &Run{
		Tool: Tool{
			Driver: &Driver{
				Name:           toolName,
				InformationURI: informationURI,
			},
		},
	}
	return run
}

// AddArtifact adds an artifact to the run and returns a pointer to it
func (run *Run) AddArtifact() *Artifact {
	a := &Artifact{
		Length: -1,
	}
	run.Artifacts = append(run.Artifacts, a)
	return a
}

// AddRule returns an existing Rule for the ruleID or creates a new Rule and returns a pointer to it
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

// AddResult returns an existing Result or creates a new one and returns a pointer to it
func (run *Run) AddResult(ruleID string) *Result {
	result := newRuleResult(ruleID)
	run.Results = append(run.Results, result)
	return result
}

// GetRuleById finds a rule by a given rule ID and returns a pointer to it
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

// GetResultByRuleId finds the result for a ruleId and returns a pointer to it
func (run *Run) GetResultByRuleId(ruleId string) (*Result, error) {
	for _, result := range run.Results {
		if *result.RuleID == ruleId {
			return result, nil
		}
	}
	return nil, fmt.Errorf("couldn't find a result for rule %s", ruleId)
}

func (run *Run) DedupeArtifacts() error {
	dupes := map[*Artifact]bool{}
	deduped := []*Artifact{}

	for _, a := range run.Artifacts {
		if _, ok := dupes[a]; !ok {
			dupes[a] = true
			deduped = append(deduped, a)
		}
	}
	run.Artifacts = deduped
	return nil
}
