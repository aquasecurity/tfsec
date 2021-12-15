package dynamodb

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/dynamodb"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS086",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_dynamodb_table"},
		Base:           dynamodb.CheckEnableRecovery,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("point_in_time_recovery") {
				results.Add("Resource doesn't have point in time recovery", resourceBlock)
				return
			}

			pointBlock := resourceBlock.GetBlock("point_in_time_recovery")
			if pointBlock.MissingChild("enabled") {
				results.Add("Resource doesn't have point in time recovery enabled", pointBlock)
				return
			}
			enabledAttr := pointBlock.GetAttribute("enabled")
			if enabledAttr.IsFalse() {
				results.Add("Resource doesn't have point in time recovery enabled", enabledAttr)
			}

			return results
		},
	})
}
