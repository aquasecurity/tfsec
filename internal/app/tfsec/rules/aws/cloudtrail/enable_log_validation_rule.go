package cloudtrail

import (
	"github.com/aquasecurity/defsec/rules/aws/cloudtrail"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS064",
		BadExample: []string{`
 resource "aws_cloudtrail" "bad_example" {
   is_multi_region_trail = true
 
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
 }
 `},
		GoodExample: []string{`
 resource "aws_cloudtrail" "good_example" {
   is_multi_region_trail = true
   enable_log_file_validation = true
 
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#enable_log_file_validation",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudtrail"},
		Base:           cloudtrail.CheckEnableLogValidation,
	})
}
