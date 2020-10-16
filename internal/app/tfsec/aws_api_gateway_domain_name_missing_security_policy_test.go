package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks/aws"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSMissingSecurityPolicy(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check aws_api_gateway_domain_name with outdated policy",
			source: `
resource "aws_api_gateway_domain_name" "my-resource" {
	security_policy = "TLS_1_0"
}`,
			mustIncludeResultCode: aws.AWSApiGatewayDomainNameOutdatedSecurityPolicy,
		},
		{
			name: "check aws_api_gateway_domain_name with empty security policy",
			source: `
resource "aws_api_gateway_domain_name" "my-resource" {
	security_policy = ""
}`,
			mustIncludeResultCode: aws.AWSApiGatewayDomainNameOutdatedSecurityPolicy,
		},
		{
			name: "check aws_api_gateway_domain_name without security policy",
			source: `
resource "aws_api_gateway_domain_name" "my-resource" {
 domain=""
}`,
			mustIncludeResultCode: aws.AWSApiGatewayDomainNameOutdatedSecurityPolicy,
		},
		{
			name: "check aws_api_gateway_domain_name with ok policy",
			source: `
resource "aws_api_gateway_domain_name" "my-resource" {
	security_policy = "TLS_1_2"
}`,
			mustExcludeResultCode: aws.AWSApiGatewayDomainNameOutdatedSecurityPolicy,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
