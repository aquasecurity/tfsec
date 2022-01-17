package rds

import (
	"github.com/aquasecurity/defsec/rules/aws/rds"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS051",
		BadExample: []string{`
 resource "aws_rds_cluster" "bad_example" {
   name       = "bar"
   kms_key_id = ""
 }`},
		GoodExample: []string{`
 resource "aws_rds_cluster" "good_example" {
   name              = "bar"
   kms_key_id  = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
   storage_encrypted = true
 }`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_rds_cluster"},
		Base:           rds.CheckEncryptClusterStorageData,
	})
}
