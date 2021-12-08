package sarif

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"
)

type RunOption int

const IncludeEmptyResults RunOption = iota

// Run type represents a run of a tool
type Run struct { // https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10540922
	PropertyBag
	Tool        Tool          `json:"tool"`
	Invocations []*Invocation `json:"invocations,omitempty"`
	Artifacts   []*Artifact   `json:"artifacts,omitempty"`
	Results     []*Result     `json:"results"`
	Properties  Properties    `json:"properties,omitempty"`
}

// NewRun allows the creation of a new Run
func NewRun(toolName, informationURI string) *Run {
	run := &Run{
		Tool: Tool{
			Driver: &ToolComponent{
				Name:           toolName,
				InformationURI: &informationURI,
			},
		},
		Results: []*Result{},
	}

	return run
}

// AddInvocation adds an invocation to the run and returns a pointer to it
func (run *Run) AddInvocation(executionSuccessful bool) *Invocation {
	i := &Invocation{
		ExecutionSuccessful: executionSuccessful,
	}
	run.Invocations = append(run.Invocations, i)
	return i
}

// AddArtifact adds an artifact to the run and returns a pointer to it
func (run *Run) AddArtifact() *Artifact {
	a := &Artifact{
		Length: -1,
	}
	run.Artifacts = append(run.Artifacts, a)
	return a
}

// AddDistinctArtifact will handle deduplication of simple artifact additions
func (run *Run) AddDistinctArtifact(uri string) *Artifact {
	for _, artifact := range run.Artifacts {
		if *artifact.Location.URI == uri {
			return artifact
		}
	}

	a := &Artifact{
		Length: -1,
	}
	a.WithLocation(NewSimpleArtifactLocation(uri))

	run.Artifacts = append(run.Artifacts, a)
	return a
}

// AddRule returns an existing ReportingDescriptor for the ruleID or creates a new ReportingDescriptor and returns a pointer to it
func (run *Run) AddRule(ruleID string) *ReportingDescriptor {
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

func (run *Run) AttachPropertyBag(pb *PropertyBag) {
	run.Properties = pb.Properties
}

// GetRuleById finds a rule by a given rule ID and returns a pointer to it
func (run *Run) GetRuleById(ruleId string) (*ReportingDescriptor, error) {
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

func (run *Run) AddProperty(key string, value cty.Value) {
	run.Properties[key] = value
}
