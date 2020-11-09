package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSRDSPerformanceInsughtsEncryptionNotEnabled scanner.RuleCode = "AWS053"
const AWSRDSPerformanceInsughtsEncryptionNotEnabledDescription scanner.RuleSummary = "Encryption for RDS Perfomance Insights should be enabled."
const AWSRDSPerformanceInsughtsEncryptionNotEnabledExplanation = `
When enabling Performance Insights on an RDS cluster or RDS DB Instance, and encryption key should be provided.

The encryption key specified in ` + "`" + `performance_insights_kms_key_id` + "`" + ` references a KMS ARN
`
const AWSRDSPerformanceInsughtsEncryptionNotEnabledBadExample = `
resource "aws_rds_cluster_instance" "foo" {
  name                 = "bar"
  performance_insights_enabled = true
  performance_insights_kms_key_id = ""
}
`
const AWSRDSPerformanceInsughtsEncryptionNotEnabledGoodExample = `
resource "aws_rds_cluster_instance" "foo" {
  name                 = "bar"
  performance_insights_enabled = true
  performance_insights_kms_key_id = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSRDSPerformanceInsughtsEncryptionNotEnabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSRDSPerformanceInsughtsEncryptionNotEnabledDescription,
			Explanation: AWSRDSPerformanceInsughtsEncryptionNotEnabledExplanation,
			BadExample:  AWSRDSPerformanceInsughtsEncryptionNotEnabledBadExample,
			GoodExample: AWSRDSPerformanceInsughtsEncryptionNotEnabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster_instance#performance_insights_kms_key_id",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#performance_insights_kms_key_id",
				"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.htm",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_rds_cluster_instance", "aws_db_instance"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.HasChild("performance_insights_enabled") && block.GetAttribute("performance_insights_enabled").IsTrue() {
				if block.MissingChild("performance_insights_kms_key_id") || block.GetAttribute("performance_insights_kms_key_id").IsEmpty() {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' defines Performance Insights without encryption key specified.", block.FullName()),
							block.Range(),
							scanner.SeverityError,
						),
					}
				}
			}

			return nil
		},
	})
}
