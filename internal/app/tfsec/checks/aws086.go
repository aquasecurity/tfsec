package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSDynamoDBRecoveryEnabled scanner.RuleCode = "AWS086"
const AWSDynamoDBRecoveryEnabledDescription scanner.RuleSummary = "Point in time recovery should be enabled to protect DynamoDB table"
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
	scanner.RegisterCheck(scanner.Check{
		Code: AWSDynamoDBRecoveryEnabled,
		Documentation: scanner.CheckDocumentation{
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
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_dynamodb_table"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("point_in_time_recovery") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' doesn't have point in time recovery", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			}

			poitBlock := block.GetBlock("point_in_time_recovery")
			if poitBlock.MissingChild("enabled") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' doesn't have point in time recovery enabled", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			}
			enabledAttr := poitBlock.GetAttribute("enabled")
			if enabledAttr.IsFalse() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' doesn't have point in time recovery enabled", block.FullName()),
						enabledAttr.Range(),
						enabledAttr,
						scanner.SeverityWarning,
					),
				}
			}

			return nil
		},
	})
}
