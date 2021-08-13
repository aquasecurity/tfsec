package s3

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS077",
		Service:   "s3",
		ShortCode: "enable-versioning",
		Documentation: rule.RuleDocumentation{
			Summary:    "S3 Data should be versioned",
			Impact:     "Deleted or modified data would not be recoverable",
			Resolution: "Enable versioning to protect against accidental/malicious removal or modification",
			Explanation: `
Versioning in Amazon S3 is a means of keeping multiple variants of an object in the same bucket. 
You can use the S3 Versioning feature to preserve, retrieve, and restore every version of every object stored in your buckets. 
With versioning you can recover more easily from both unintended user actions and application failures.
`,
			BadExample: []string{`
resource "aws_s3_bucket" "bad_example" {

}
`},
			GoodExample: []string{`
resource "aws_s3_bucket" "good_example" {

	versioning {
		enabled = true
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#versioning",
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_s3_bucket"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("versioning") {
				set.AddResult().
					WithDescription("Resource '%s' does not have versioning enabled", resourceBlock.FullName())
				return
			}

			versioningBlock := resourceBlock.GetBlock("versioning")
			if versioningBlock.HasChild("enabled") && versioningBlock.GetAttribute("enabled").IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' has versioning block but is disabled", resourceBlock.FullName()).WithBlock(versioningBlock)
			}
		},
	})
}
