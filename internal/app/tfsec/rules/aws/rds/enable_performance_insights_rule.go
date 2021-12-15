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
		LegacyID: "AWS053",

		When enabling Performance Insights on an RDS cluster or RDS DB Instance, and encryption key should be provided.

		The encryption key specified in ` + "`" + `performance_insights_kms_key_id` + "`" + ` references a KMS ARN
		`,
		BadExample: []string{`
		resource "aws_rds_cluster_instance" "bad_example" {
		name = "bar"
		performance_insights_enabled = true
		performance_insights_kms_key_id = ""
		}
		`},
		GoodExample: []string{`
		resource "aws_rds_cluster_instance" "good_example" {
		name = "bar"
		performance_insights_enabled = true
		performance_insights_kms_key_id = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
		}
	`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster_instance#performance_insights_kms_key_id",
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#performance_insights_kms_key_id",
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.htm",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_rds_cluster_instance", "aws_db_instance"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.HasChild("performance_insights_enabled") && resourceBlock.GetAttribute("performance_insights_enabled").IsTrue() {
				if resourceBlock.MissingChild("performance_insights_kms_key_id") {
					results.Add("Resource defines Performance Insights without encryption key specified.", resourceBlock)
					return
				}

				if keyAttr := resourceBlock.GetAttribute("performance_insights_kms_key_id"); keyAttr.IsEmpty() {
					results.Add("Resource defines Performance Insights without encryption key specified.", ?)
				}
			}

			return results
		},
	})
}
