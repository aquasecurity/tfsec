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
		LegacyID: "AWS081",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_dax_cluster"},
		Base:           dynamodb.CheckEnableAtRestEncryption,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if resourceBlock.MissingChild("server_side_encryption") {
				results.Add("DAX cluster '%s' does not have server side encryption configured. By default it is disabled.", resourceBlock)
				return
			}

			sseBlock := resourceBlock.GetBlock("server_side_encryption")
			if sseBlock.MissingChild("enabled") {
				results.Add("DAX cluster '%s' server side encryption block is empty. By default SSE is disabled.", sseBlock)
			}

			if sseEnabledAttr := sseBlock.GetAttribute("enabled"); sseEnabledAttr.IsFalse() {
				results.Add("DAX cluster '%s' has disabled server side encryption", sseEnabledAttr)
			}

			return results
		},
	})
}
