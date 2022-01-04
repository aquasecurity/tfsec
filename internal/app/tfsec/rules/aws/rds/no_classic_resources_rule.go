package rds

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/rds"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS003",
		BadExample: []string{`
 resource "aws_db_security_group" "bad_example" {
   # ...
 }
 `},
		GoodExample: []string{`
 resource "aws_security_group" "good_example" {
   # ...
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_security_group",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_security_group", "aws_redshift_security_group", "aws_elasticache_security_group"},
		Base:           rds.CheckNoClassicResources,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			results.Add("Resource uses EC2 Classic. Use a VPC instead.", resourceBlock)
			return results
		},
	})
}
