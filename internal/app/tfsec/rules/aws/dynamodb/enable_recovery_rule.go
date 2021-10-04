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
		LegacyID:  "AWS086",
		Service:   "dynamodb",
		ShortCode: "enable-recovery",
		Documentation: rule.RuleDocumentation{
			Summary: "Point in time recovery should be enabled to protect DynamoDB table",
			Explanation: `
DynamoDB tables should be protected against accidentally or malicious write/delete actions by ensuring that there is adequate protection.

By enabling point-in-time-recovery you can restore to a known point in the event of loss of data.
`,
			Impact:     "Accidental or malicious writes and deletes can't be rolled back",
			Resolution: "Enable point in time recovery",
			BadExample: []string{`
resource "aws_dynamodb_table" "bad_example" {
	name             = "example"
	hash_key         = "TestTableHashKey"
	billing_mode     = "PAY_PER_REQUEST"
	stream_enabled   = true
	stream_view_type = "NEW_AND_OLD_IMAGES"
  
	attribute {
	  name = "TestTableHashKey"
	  type = "S"
	}
}
`},
			GoodExample: []string{`
resource "aws_dynamodb_table" "good_example" {
	name             = "example"
	hash_key         = "TestTableHashKey"
	billing_mode     = "PAY_PER_REQUEST"
	stream_enabled   = true
	stream_view_type = "NEW_AND_OLD_IMAGES"
  
	attribute {
	  name = "TestTableHashKey"
	  type = "S"
	}

	point_in_time_recovery {
		enabled = true
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table#point_in_time_recovery",
				"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_dynamodb_table"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("point_in_time_recovery") {
				set.AddResult().
					WithDescription("Resource '%s' doesn't have point in time recovery", resourceBlock.FullName())
				return
			}

			pointBlock := resourceBlock.GetBlock("point_in_time_recovery")
			if pointBlock.MissingChild("enabled") {
				set.AddResult().
					WithDescription("Resource '%s' doesn't have point in time recovery enabled", resourceBlock.FullName()).
					WithBlock(pointBlock)
				return
			}
			enabledAttr := pointBlock.GetAttribute("enabled")
			if enabledAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' doesn't have point in time recovery enabled", resourceBlock.FullName()).
					WithAttribute(enabledAttr)
			}

		},
	})
}
