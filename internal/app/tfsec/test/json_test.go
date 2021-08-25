package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
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
			mustIncludeResultCode: "aws-vpc-no-public-ingress-sgr",
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
			mustIncludeResultCode: "aws-vpc-add-description-to-security-group",
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
			mustExcludeResultCode: "aws-vpc-no-public-ingress-sgr",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := testutil.ScanJSON(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
