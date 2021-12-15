package dynamodb

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/dynamodb"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS092",
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
   
 	replica {
 	  region_name = "us-east-2"
 	}
   
 	replica {
 	  region_name = "us-west-2"
 	}
   }
 `},
		GoodExample: []string{`
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
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table#server_side_encryption",
			"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_dynamodb_table"},
		Base:           dynamodb.CheckTableCustomerKey,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("server_side_encryption") {
				results.Add("Resource is not using KMS CMK for encryption", resourceBlock)
				return
			}

			sseBlock := resourceBlock.GetBlock("server_side_encryption")
			enabledAttr := sseBlock.GetAttribute("enabled")
			if enabledAttr.IsFalse() {
				results.Add("Resource has server side encryption configured but disabled", enabledAttr)
			}

			if sseBlock.HasChild("kms_key_arn") {
				keyIdAttr := sseBlock.GetAttribute("kms_key_arn")
				if keyIdAttr.Equals("alias/aws/dynamodb") {
					results.Add("Resource has KMS encryption configured but is using the default aws key", keyIdAttr)
				}
			}

			return results
		},
	})
}
