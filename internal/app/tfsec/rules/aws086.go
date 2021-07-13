package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSDynamoDBRecoveryEnabled = "AWS086"
const AWSDynamoDBRecoveryEnabledDescription = "Point in time recovery should be enabled to protect DynamoDB table"
const AWSDynamoDBRecoveryEnabledImpact = "Accidental or malicious writes and deletes can't be rolled back"
const AWSDynamoDBRecoveryEnabledResolution = "Enable point in time recovery"
const AWSDynamoDBRecoveryEnabledExplanation = `
DynamoDB tables should be protected against accidentally or malicious write/delete actions by ensuring that there is adequate protection.

By enabling point-in-time-recovery you can restore to a known point in the event of loss of data.
`
const AWSDynamoDBRecoveryEnabledBadExample = `
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
`
const AWSDynamoDBRecoveryEnabledGoodExample = `
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
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSDynamoDBRecoveryEnabled,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSDynamoDBRecoveryEnabledDescription,
			Explanation: AWSDynamoDBRecoveryEnabledExplanation,
			Impact:      AWSDynamoDBRecoveryEnabledImpact,
			Resolution:  AWSDynamoDBRecoveryEnabledResolution,
			BadExample:  AWSDynamoDBRecoveryEnabledBadExample,
			GoodExample: AWSDynamoDBRecoveryEnabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table#point_in_time_recovery",
				"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_dynamodb_table"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("point_in_time_recovery") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' doesn't have point in time recovery", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			poitBlock := resourceBlock.GetBlock("point_in_time_recovery")
			if poitBlock.MissingChild("enabled") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' doesn't have point in time recovery enabled", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}
			enabledAttr := poitBlock.GetAttribute("enabled")
			if enabledAttr.IsFalse() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' doesn't have point in time recovery enabled", resourceBlock.FullName())).
						WithRange(enabledAttr.Range()).
						WithAttributeAnnotation(enabledAttr),
				)
			}

		},
	})
}
