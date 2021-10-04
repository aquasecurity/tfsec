package dynamodb

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
		LegacyID:  "AWS081",
		Service:   "dynamodb",
		ShortCode: "enable-at-rest-encryption",
		Documentation: rule.RuleDocumentation{
			Summary:    "DAX Cluster should always encrypt data at rest",
			Impact:     "Data can be freely read if compromised",
			Resolution: "Enable encryption at rest for DAX Cluster",
			Explanation: `
Amazon DynamoDB Accelerator (DAX) encryption at rest provides an additional layer of data protection by helping secure your data from unauthorized access to the underlying storage.
`,
			BadExample: []string{`
resource "aws_dax_cluster" "bad_example" {
	// no server side encryption at all
}

resource "aws_dax_cluster" "bad_example" {
	// other DAX config

	server_side_encryption {
		// empty server side encryption config
	}
}

resource "aws_dax_cluster" "bad_example" {
	// other DAX config

	server_side_encryption {
		enabled = false // disabled server side encryption
	}
}
`},
			GoodExample: []string{`
resource "aws_dax_cluster" "good_example" {
	// other DAX config

	server_side_encryption {
		enabled = true // enabled server side encryption
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dax_cluster#server_side_encryption",
				"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionAtRest.html",
				"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dax-cluster.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_dax_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if resourceBlock.MissingChild("server_side_encryption") {
				set.AddResult().
					WithDescription("DAX cluster '%s' does not have server side encryption configured. By default it is disabled.", resourceBlock.FullName())
				return
			}

			sseBlock := resourceBlock.GetBlock("server_side_encryption")
			if sseBlock.MissingChild("enabled") {
				set.AddResult().
					WithDescription("DAX cluster '%s' server side encryption block is empty. By default SSE is disabled.", resourceBlock.FullName()).
					WithBlock(sseBlock)
			}

			if sseEnabledAttr := sseBlock.GetAttribute("enabled"); sseEnabledAttr.IsFalse() {
				set.AddResult().
					WithDescription("DAX cluster '%s' has disabled server side encryption", resourceBlock.FullName()).
					WithAttribute(sseEnabledAttr)
			}

		},
	})
}
