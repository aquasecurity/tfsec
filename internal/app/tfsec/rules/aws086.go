package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSDynamoDBRecoveryEnabled = "AWS086"
const AWSDynamoDBRecoveryEnabledDescription = "Point in time recovery should be enabled to protect DynamoDB table"
const AWSDynamoDBRecoveryEnabledImpact = "Accidental or malicious writes and deletes can't be rolled back"
const AWSDynamoDBRecoveryEnabledResolution = "Enable point in time recovery"
const AWSDynamoDBRecoveryEnabledExplanation = `
DynamoDB tables should be protected against accidently or malicious write/delete actions by ensuring that there is adaquate protection.

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
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_dynamodb_table"},
		CheckFunc: func(set result.Set, block *block.Block, _ *hclcontext.Context) {

			if block.MissingChild("point_in_time_recovery") {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' doesn't have point in time recovery", block.FullName()),
						).WithRange(block.Range()).WithSeverity(
						severity.Warning,
					),
				}
			}

			poitBlock := block.GetBlock("point_in_time_recovery")
			if poitBlock.MissingChild("enabled") {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' doesn't have point in time recovery enabled", block.FullName()),
						).WithRange(block.Range()).WithSeverity(
						severity.Warning,
					),
				}
			}
			enabledAttr := poitBlock.GetAttribute("enabled")
			if enabledAttr.IsFalse() {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' doesn't have point in time recovery enabled", block.FullName()),
						enabledAttr.Range(),
						enabledAttr,
						severity.Warning,
					),
				}
			}

			return nil
		},
	})
}
