package test

import (
	"testing"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func TestScanningJSON(t *testing.T) {

	var tests = []struct {
		name       string
		source     string
		shouldFail bool
	}{
		{
			name: "check results are picked up in tf json configs",
			source: `
			{
				"provider": {
					"aws": {
						"profile": null,
						"region": "eu-west-1"
					}
				},
				"resource": {
					"bad": {
						"thing": {
							"type": "ingress",
							"cidr_blocks": ["0.0.0.0/0"],
							"description": "testing"
						}
					}
				}
			}`,
			shouldFail: true,
		},
		{
			name: "check attributes are checked in tf json configs",
			source: `
			{
				"provider": {
					"aws": {
						"profile": null,
						"region": "eu-west-1"
					}
				},
				"resource": {
					"bad": {
						"or_not": {
							"secure": true
						}
					}
				}
			}`,
			shouldFail: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r1 := rule.Rule{
				LegacyID: "ABC123",
				Base: rules.Register(rules.Rule{
					Provider:  provider.AWSProvider,
					Service:   "service",
					ShortCode: "abc123",
					Severity:  severity.High,
				}, nil),
				RequiredLabels: []string{"bad"},
				CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
					if resourceBlock.GetAttribute("secure").IsTrue() {
						return
					}
					results.Add("something", resourceBlock)
					return
				},
			}
			scanner.RegisterCheckRule(r1)
			defer scanner.DeregisterCheckRule(r1)

			results := testutil.ScanJSON(test.source, t)
			var include, exclude string
			if test.shouldFail {
				include = r1.ID()
			} else {
				exclude = r1.ID()
			}
			testutil.AssertCheckCode(t, include, exclude, results)
		})
	}
}
