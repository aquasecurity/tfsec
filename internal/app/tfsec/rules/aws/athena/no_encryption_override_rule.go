package athena

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/athena"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS060",
		BadExample: []string{`
 resource "aws_athena_workgroup" "bad_example" {
   name = "example"
 
   configuration {
     enforce_workgroup_configuration    = false
     publish_cloudwatch_metrics_enabled = true
 
     result_configuration {
       output_location = "s3://${aws_s3_bucket.example.bucket}/output/"
 
       encryption_configuration {
         encryption_option = "SSE_KMS"
         kms_key_arn       = aws_kms_key.example.arn
       }
     }
   }
 }
 
 resource "aws_athena_workgroup" "bad_example" {
   name = "example"
 
 }
 `},
		GoodExample: []string{`
 resource "aws_athena_workgroup" "good_example" {
   name = "example"
 
   configuration {
     enforce_workgroup_configuration    = true
     publish_cloudwatch_metrics_enabled = true
 
     result_configuration {
       output_location = "s3://${aws_s3_bucket.example.bucket}/output/"
 
       encryption_configuration {
         encryption_option = "SSE_KMS"
         kms_key_arn       = aws_kms_key.example.arn
       }
     }
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup#configuration",
			"https://docs.aws.amazon.com/athena/latest/ug/manage-queries-control-costs-with-workgroups.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_athena_workgroup"},
		Base:           athena.CheckNoEncryptionOverride,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("configuration") {
				results.Add("Resource is missing the configuration block.", resourceBlock)
				return
			}

			configBlock := resourceBlock.GetBlock("configuration")

			configBlock.HasChild("enforce_workgroup_configuration")
			enforceWorkgroupConfigAttr := configBlock.GetAttribute("enforce_workgroup_configuration")

			if enforceWorkgroupConfigAttr.IsNil() {
				return
			}

			if enforceWorkgroupConfigAttr.IsFalse() {
				results.Add("Resource has enforce_workgroup_configuration set to false.", enforceWorkgroupConfigAttr)
			}

			return results
		},
	})
}
