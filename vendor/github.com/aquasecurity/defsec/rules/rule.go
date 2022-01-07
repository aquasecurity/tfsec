package rules

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/severity"
)

type EngineMetadata struct {
	GoodExamples        []string `json:"good_examples,omitempty"`
	BadExamples         []string `json:"bad_examples,omitempty"`
	RemediationMarkdown string   `json:"remediation_markdown,omitempty"`
	Links               []string `json:"links,omitempty"`
}

type Rule struct {
	AVDID          string            `json:"avd_id"`
	ShortCode      string            `json:"short_code"`
	Summary        string            `json:"summary"`
	Explanation    string            `json:"explanation"`
	Impact         string            `json:"impact"`
	Resolution     string            `json:"resolution"`
	Provider       provider.Provider `json:"provider"`
	Service        string            `json:"service"`
	Links          []string          `json:"links"`
	Severity       severity.Severity `json:"severity"`
	Terraform      *EngineMetadata   `json:"terraform,omitempty"`
	CloudFormation *EngineMetadata   `json:"cloud_formation,omitempty"`
}

func (r Rule) LongID() string {
	return strings.ToLower(fmt.Sprintf("%s-%s-%s", r.Provider, r.Service, r.ShortCode))
}
