package main

import (
	"fmt"

	"github.com/aquasecurity/tfsec/cmd/tfsec-skeleton/requirements"
	"github.com/aquasecurity/tfsec/pkg/provider"
)

type Input struct {
	Provider       provider.Provider
	Service        string
	ShortCode      string
	Summary        string
	Explanation    string
	Impact         string
	Resolution     string
	Severity       string
	RequiredTypes  []string
	RequiredLabels []string
	Requirement    requirements.Requirement
	AttributeName  string
}

func (i Input) Validate() error {
	if i.Provider == "" {
		return fmt.Errorf("no provider specified")
	}
	if i.Service == "" {
		return fmt.Errorf("no service specified")
	}
	if i.ShortCode == "" {
		return fmt.Errorf("no short code specified")
	}
	if i.Summary == "" {
		return fmt.Errorf("no summary specified")
	}
	if i.Explanation == "" {
		return fmt.Errorf("no explanation specified")
	}
	if i.Impact == "" {
		return fmt.Errorf("no impact specified")
	}
	if i.Resolution == "" {
		return fmt.Errorf("no resolution specified")
	}
	if i.Severity == "" {
		return fmt.Errorf("no severity specified")
	}
	if len(i.RequiredTypes) == 0 {
		return fmt.Errorf("no required type(s) specified")
	}
	if len(i.RequiredLabels) == 0 {
		return fmt.Errorf("no required label(s) specified")
	}
	if i.Requirement == nil {
		return fmt.Errorf("no requirement specified")
	}
	if i.AttributeName == "" {
		return fmt.Errorf("no attribute path specified")
	}
	return nil
}
