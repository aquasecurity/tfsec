package rds

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
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
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-classic-platform.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_security_group", "aws_redshift_security_group", "aws_elasticache_security_group"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			results.Add("Resource uses EC2 Classic. Use a VPC instead.", ?)
			return results
		},
	})
}
