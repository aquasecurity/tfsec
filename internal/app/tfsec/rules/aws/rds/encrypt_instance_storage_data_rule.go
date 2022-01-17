package rds

import (
	"github.com/aquasecurity/defsec/rules/aws/rds"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS052",
		BadExample: []string{`
 resource "aws_db_instance" "bad_example" {
 	
 }
 `},
		GoodExample: []string{`
 resource "aws_db_instance" "good_example" {
 	storage_encrypted  = true
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_instance"},
		Base:           rds.CheckEncryptInstanceStorageData,
	})
}
