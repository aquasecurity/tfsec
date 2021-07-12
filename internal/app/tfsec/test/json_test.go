package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func TestScanningJSON(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check open security group rules are picked up in tf json configs",
			source: `
			{
				"provider": {
					"aws": {
						"profile": null,
						"region": "eu-west-1"
					}
				},
				"resource": {
					"aws_security_group_rule": {
						"bad-rule": {
							"type": "ingress",
							"cidr_blocks": ["0.0.0.0/0"],
							"description": "testing"
						}
					}
				}
			}`,
			mustIncludeResultCode: rules.AWSOpenIngressSecurityGroupRule,
		},
		{
			name: "check missing sgr descriptions are picked up in tf json configs",
			source: `
			{
				"provider": {
					"aws": {
						"profile": null,
						"region": "eu-west-1"
					}
				},
				"resource": {
					"aws_security_group_rule": {
						"bad-rule": {
							"type": "ingress",
							"cidr_blocks": ["127.0.0.1/32"]
						}
					}
				}
			}`,
			mustIncludeResultCode: rules.AWSNoDescriptionInSecurityGroup,
		},
		{
			name: "check valid resources are picked up in tf json configs",
			source: `
			{
				"provider": {
					"aws": {
						"profile": null,
						"region": "eu-west-1"
					}
				},
				"resource": {
					"aws_security_group_rule": {
						"bad-rule": {
							"type": "ingress",
							"cidr_blocks": ["127.0.0.1/32"],
							"description": "blah"
						}
					}
				}
			}`,
			mustExcludeResultCode: rules.AWSNoDescriptionInSecurityGroup,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanJSON(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
