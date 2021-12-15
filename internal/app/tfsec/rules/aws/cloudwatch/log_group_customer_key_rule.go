package cloudwatch

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/cloudwatch"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS089",
		BadExample: []string{`
 resource "aws_cloudwatch_log_group" "bad_example" {
 	name = "bad_example"
 
 }
 `},
		GoodExample: []string{`
 resource "aws_cloudwatch_log_group" "good_example" {
 	name = "good_example"
 
 	kms_key_id = aws_kms_key.log_key.arn
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group#kms_key_id",
			"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudwatch_log_group"},
		Base:           cloudwatch.CheckLogGroupCustomerKey,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if resourceBlock.MissingChild("kms_key_id") {
				results.Add("Resource is only using default encryption", resourceBlock)
			}
			return results
		},
	})
}
