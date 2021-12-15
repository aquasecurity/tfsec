package sqs

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS015",
		BadExample: []string{`
 resource "aws_sqs_queue" "bad_example" {
 	# no key specified
 }
 `},
		GoodExample: []string{`
 resource "aws_sqs_queue" "good_example" {
 	kms_master_key_id = "/blah"
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue#server-side-encryption-sse",
			"https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_sqs_queue"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			kmsKeyIDAttr := resourceBlock.GetAttribute("kms_master_key_id")
			if kmsKeyIDAttr.IsNil() {
				results.Add("Resource defines an unencrypted SQS queue.", ?)
			} else if kmsKeyIDAttr.IsEmpty() {
				results.Add("Resource defines an unencrypted SQS queue.", kmsKeyIDAttr)
			}

			return results
		},
	})
}
