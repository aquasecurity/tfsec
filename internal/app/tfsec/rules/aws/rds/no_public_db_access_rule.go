package rds

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS011",
		Service:   "rds",
		ShortCode: "no-public-db-access",
		Documentation: rule.RuleDocumentation{
			Summary:    "A database resource is marked as publicly accessible.",
			Impact:     "The database instance is publicly accessible",
			Resolution: "Set the database to not be publicly accessible",
			Explanation: `
Database resources should not publicly available. You should limit all access to the minimum that is required for your application to function. 
`,
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
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_db_instance", "aws_dms_replication_instance", "aws_rds_cluster_instance", "aws_redshift_cluster"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			publicAttr := resourceBlock.GetAttribute("publicly_accessible")
			if publicAttr.IsTrue() {
				set.AddResult().
					WithDescription("Resource '%s' is exposed publicly.", resourceBlock.FullName()).
					WithAttribute(publicAttr)
			}
		},
	})
}
