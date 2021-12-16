package athena

import (
	"strings"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/athena"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS059",
		BadExample: []string{`
 resource "aws_athena_database" "bad_example" {
   name   = "database_name"
   bucket = aws_s3_bucket.hoge.bucket
 }
 
 resource "aws_athena_workgroup" "bad_example" {
   name = "example"
 
   configuration {
     enforce_workgroup_configuration    = true
     publish_cloudwatch_metrics_enabled = true
 
     result_configuration {
       output_location = "s3://${aws_s3_bucket.example.bucket}/output/"
     }
   }
 }
 `},
		GoodExample: []string{`
 resource "aws_athena_database" "good_example" {
   name   = "database_name"
   bucket = aws_s3_bucket.hoge.bucket
 
   encryption_configuration {
      encryption_option = "SSE_KMS"
      kms_key_arn       = aws_kms_key.example.arn
  }
 }
 
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
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup#encryption_configuration",
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_database#encryption_configuration",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_athena_database", "aws_athena_workgroup"},
		Base:           athena.CheckEnableAtRestEncryption,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if strings.EqualFold(resourceBlock.TypeLabel(), "aws_athena_workgroup") {
				if !resourceBlock.HasChild("configuration") {
					return
				}
				configBlock := resourceBlock.GetBlock("configuration")
				if !configBlock.HasChild("result_configuration") {
					return
				}
				resourceBlock = configBlock.GetBlock("result_configuration")
			}

			if resourceBlock.MissingChild("encryption_configuration") {
				results.Add("Missing encryption configuration block.", resourceBlock)
			}

			return results
		},
	})
}
