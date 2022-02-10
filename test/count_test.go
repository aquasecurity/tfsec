package test

import (
	"testing"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/tfsec/internal/pkg/scanner"
	"github.com/aquasecurity/tfsec/internal/pkg/testutil"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/trivy-config-parsers/terraform"
	"github.com/stretchr/testify/assert"
)

func Test_ResourcesWithCount(t *testing.T) {
	var tests = []struct {
		name            string
		source          string
		expectedResults int
	}{
		{
			name: "unspecified count defaults to 1",
			source: `
			resource "bad" "this" {}
`,
			expectedResults: 1,
		},
		{
			name: "count is literal 1",
			source: `
			resource "bad" "this" {
				count = 1
			}
`,
			expectedResults: 1,
		},
		{
			name: "count is literal 99",
			source: `
			resource "bad" "this" {
				count = 99
			}
`,
			expectedResults: 99,
		},
		{
			name: "count is literal 0",
			source: `
			resource "bad" "this" {
				count = 0
			}
`,
			expectedResults: 0,
		},
		{
			name: "count is 0 from variable",
			source: `
			variable "count" {
				default = 0
			}
			resource "bad" "this" {
				count = var.count
			}
`,
			expectedResults: 0,
		},
		{
			name: "count is 1 from variable",
			source: `
			variable "count" {
				default = 1
			}
			resource "bad" "this" {
				count =  var.count
			}
`,
			expectedResults: 1,
		},
		{
			name: "count is 1 from variable without default",
			source: `
			variable "count" {
			}
			resource "bad" "this" {
				count =  var.count
			}
`,
			expectedResults: 1,
		},
		{
			name: "count is 0 from conditional",
			source: `
			variable "enabled" {
				default = false
			}
			resource "bad" "this" {
				count = var.enabled ? 1 : 0
			}
`,
			expectedResults: 0,
		},
		{
			name: "count is 1 from conditional",
			source: `
			variable "enabled" {
				default = true
			}
			resource "bad" "this" {
				count = var.enabled ? 1 : 0
			}
`,
			expectedResults: 1,
		},
		{
			name: "issue 962",
			source: `
			resource "something" "else" {
				count = 2
				ok = true
			}

			resource "bad" "bad" {
				secure = something.else[0].ok
			}	
`,
			expectedResults: 0,
		},
		{
			name: "Test use of count.index",
			source: `
resource "bad" "thing" {
	count = 1
	secure = var.things[count.index]["ok"]
}
	
variable "things" {
	description = "A list of maps that creates a number of sg"
	type = list(map(string))
	
	default = [
		{
			ok = true
		}
	]
}
			`,
			expectedResults: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r1 := rule.Rule{
				Base: rules.Register(
					rules.Rule{
						Provider:  provider.AWSProvider,
						Service:   "service",
						ShortCode: "abc123",
						Severity:  severity.High,
					},
					nil,
				),
				RequiredLabels: []string{"bad"},
				CheckTerraform: func(resourceBlock *terraform.Block, _ *terraform.Module) (results rules.Results) {
					if resourceBlock.GetAttribute("secure").IsTrue() {
						return
					}
					results.Add(
						"example problem",
						resourceBlock,
					)
					return
				},
			}
			scanner.RegisterCheckRule(r1)
			defer scanner.DeregisterCheckRule(r1)
			results := testutil.ScanHCL(test.source, t)
			var include string
			var exclude string
			if test.expectedResults > 0 {
				include = r1.ID()
			} else {
				exclude = r1.ID()
			}
			assert.Equal(t, test.expectedResults, len(results))
			if include != "" {
				testutil.AssertRuleFound(t, include, results, "false negative found")
			}
			if exclude != "" {
				testutil.AssertRuleNotFound(t, exclude, results, "false positive found")
			}
		})
	}
}
