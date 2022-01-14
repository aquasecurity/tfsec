package dynamodb

import (
	"github.com/aquasecurity/defsec/rules/aws/dynamodb"
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
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_dax_cluster"},
		Base:           dynamodb.CheckEnableAtRestEncryption,
	})
}
