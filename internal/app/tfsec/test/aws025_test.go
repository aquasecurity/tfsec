package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSMissingSecurityPolicy(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check aws_api_gateway_domain_name with outdated policy",
			source: `
resource "aws_api_gateway_domain_name" "my-resource" {
	security_policy = "TLS_1_0"
}`,
			mustIncludeResultCode: rules.AWSApiGatewayDomainNameOutdatedSecurityPolicy,
		},
		{
			name: "check aws_api_gateway_domain_name with empty security policy",
			source: `
resource "aws_api_gateway_domain_name" "my-resource" {
	security_policy = ""
}`,
			mustIncludeResultCode: rules.AWSApiGatewayDomainNameOutdatedSecurityPolicy,
		},
		{
			name: "check aws_api_gateway_domain_name without security policy",
			source: `
resource "aws_api_gateway_domain_name" "my-resource" {
 domain=""
}`,
			mustIncludeResultCode: rules.AWSApiGatewayDomainNameOutdatedSecurityPolicy,
		},
		{
			name: "check aws_api_gateway_domain_name with ok policy",
			source: `
resource "aws_api_gateway_domain_name" "my-resource" {
	security_policy = "TLS_1_2"
}`,
			mustExcludeResultCode: rules.AWSApiGatewayDomainNameOutdatedSecurityPolicy,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
