package cloudfront

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/cloudfront"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
			"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-s3-origin.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudfront_distribution"},
		Base:           cloudfront.CheckEnforceHttps,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			defaultBehaviorBlock := resourceBlock.GetBlock("default_cache_behavior")
			if defaultBehaviorBlock.IsNil() {
				results.Add("Resource defines a CloudFront distribution that allows unencrypted communications (missing default_cache_behavior block).", resourceBlock)
				return
			}

			protocolPolicyAttr := defaultBehaviorBlock.GetAttribute("viewer_protocol_policy")
			if protocolPolicyAttr.IsNil() {
				results.Add("Resource defines a CloudFront distribution that allows unencrypted communications (missing viewer_protocol_policy block).", defaultBehaviorBlock)
				return
			}
			if protocolPolicyAttr.Equals("allow-all") {
				results.Add("Resource defines a CloudFront distribution that allows unencrypted communications.", protocolPolicyAttr)
				return
			}

			orderedBehaviorBlocks := resourceBlock.GetBlocks("ordered_cache_behavior")
			for _, orderedBehaviorBlock := range orderedBehaviorBlocks {
				orderedProtocolPolicyAttr := orderedBehaviorBlock.GetAttribute("viewer_protocol_policy")
				if orderedProtocolPolicyAttr.IsNil() {
					results.Add("Resource defines a CloudFront distribution that allows unencrypted communications (missing viewer_protocol_policy block).", orderedBehaviorBlock)
				} else if orderedProtocolPolicyAttr.Equals("allow-all") {
					results.Add("Resource defines a CloudFront distribution that allows unencrypted communications.", orderedProtocolPolicyAttr)
				}
			}

			return results
		},
	})
}
