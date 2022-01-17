package rds

import (
	"github.com/aquasecurity/defsec/rules/aws/rds"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS011",
		BadExample: []string{`
 resource "aws_db_instance" "bad_example" {
 	publicly_accessible = true
 }
 `},
		GoodExample: []string{`
 resource "aws_db_instance" "good_example" {
 	publicly_accessible = false
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_instance", "aws_dms_replication_instance", "aws_rds_cluster_instance", "aws_redshift_cluster"},
		Base:           rds.CheckNoPublicDbAccess,
	})
}
