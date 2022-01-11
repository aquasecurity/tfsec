package cloudfront

import (
	"github.com/aquasecurity/defsec/rules/aws/cloudfront"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS021",
		BadExample: []string{`
 resource "aws_cloudfront_distribution" "bad_example" {
   viewer_certificate {
     cloudfront_default_certificate = true
     minimum_protocol_version = "TLSv1.0"
   }
 }
 `},
		GoodExample: []string{`
 resource "aws_cloudfront_distribution" "good_example" {
   viewer_certificate {
     cloudfront_default_certificate = true
     minimum_protocol_version = "TLSv1.2_2021"
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#minimum_protocol_version",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudfront_distribution"},
		Base:           cloudfront.CheckUseSecureTlsPolicy,
	})
}
