package cloudfront

import (
	"github.com/aquasecurity/defsec/rules/aws/cloudfront"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS020",
		BadExample: []string{`
 resource "aws_cloudfront_distribution" "bad_example" {
 	default_cache_behavior {
 	    viewer_protocol_policy = "allow-all"
 	  }
 }
 `},
		GoodExample: []string{`
 resource "aws_cloudfront_distribution" "good_example" {
 	default_cache_behavior {
 	    viewer_protocol_policy = "redirect-to-https"
 	  }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#viewer_protocol_policy",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudfront_distribution"},
		Base:           cloudfront.CheckEnforceHttps,
	})
}
