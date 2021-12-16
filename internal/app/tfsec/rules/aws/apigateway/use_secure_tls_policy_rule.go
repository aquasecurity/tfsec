package apigateway

import (
	"github.com/aquasecurity/defsec/rules/aws/apigateway"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS025",
		BadExample: []string{`
 resource "aws_api_gateway_domain_name" "bad_example" {
 	security_policy = "TLS_1_0"
 }
 `},
		GoodExample: []string{`
 resource "aws_api_gateway_domain_name" "good_example" {
 	security_policy = "TLS_1_2"
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_domain_name#security_policy",
		},
		Base: apigateway.CheckUseSecureTlsPolicy,
	})
}
