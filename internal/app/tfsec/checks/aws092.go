package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSDynamoDBTableEncryption scanner.RuleCode = "AWS092"
const AWSDynamoDBTableEncryptionDescription scanner.RuleSummary = "DynamoDB tables should use at rest encyption with a Customer Managed Key"
const AWSDynamoDBTableEncryptionImpact = "Using AWS managed keys does not allow for fine grained control"
const AWSDynamoDBTableEncryptionResolution = "Enable server side encrytion with a customer managed key"
const AWSDynamoDBTableEncryptionExplanation = `
DynamoDB tables are encrypted by default using AWS managed encryption keys. To increase control of the encryption and control the management of factors like key rotation, use a Customer Managed Key.
`
const AWSDynamoDBTableEncryptionBadExample = `
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
  
	replica {
	  region_name = "us-east-2"
	}
  
	replica {
	  region_name = "us-west-2"
	}
  }
`
const AWSDynamoDBTableEncryptionGoodExample = `
resource "aws_kms_key" "dynamo_db_kms" {
	enable_key_rotation = true
}

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
  
	replica {
	  region_name = "us-east-2"
	}
  
	replica {
	  region_name = "us-west-2"
	}

	server_side_encryption {
		enabled     = true
		kms_key_arn = aws_kms_key.dynamo_db_kms.key_id
	}
  }
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSDynamoDBTableEncryption,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSDynamoDBTableEncryptionDescription,
			Explanation: AWSDynamoDBTableEncryptionExplanation,
			Impact:      AWSDynamoDBTableEncryptionImpact,
			Resolution:  AWSDynamoDBTableEncryptionResolution,
			BadExample:  AWSDynamoDBTableEncryptionBadExample,
			GoodExample: AWSDynamoDBTableEncryptionGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table#server_side_encryption",
				"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_dynamodb_table"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("server_side_encryption") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' is not using KMS CMK for encryption", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			}

			sseBlock := block.GetBlock("server_side_encryption")
			enabledAttr := sseBlock.GetAttribute("enabled")
			if enabledAttr.IsFalse() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' has server side encryption configured but disabled", block.FullName()),
						enabledAttr.Range(),
						enabledAttr,
						scanner.SeverityWarning,
					),
				}
			}

			if sseBlock.HasChild("kms_key_arn") {
				keyIdAttr := sseBlock.GetAttribute("kms_key_arn")
				if keyIdAttr.Equals("alias/aws/dynamodb") {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' has KMS encryption configured but is using the default aws key", block.FullName()),
							keyIdAttr.Range(),
							keyIdAttr,
							scanner.SeverityWarning,
						),
					}
				}
			}

			return nil
		},
	})
}
