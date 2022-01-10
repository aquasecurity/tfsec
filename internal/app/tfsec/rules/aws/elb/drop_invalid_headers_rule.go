package elb

import (
	"github.com/aquasecurity/defsec/rules/aws/elb"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS083",
		BadExample: []string{`
 resource "aws_alb" "bad_example" {
 	name               = "bad_alb"
 	internal           = false
 	load_balancer_type = "application"
 	
 	access_logs {
 	  bucket  = aws_s3_bucket.lb_logs.bucket
 	  prefix  = "test-lb"
 	  enabled = true
 	}
   
 	drop_invalid_header_fields = false
   }
 `},
		GoodExample: []string{`
 resource "aws_alb" "good_example" {
 	name               = "good_alb"
 	internal           = false
 	load_balancer_type = "application"
 	
 	access_logs {
 	  bucket  = aws_s3_bucket.lb_logs.bucket
 	  prefix  = "test-lb"
 	  enabled = true
 	}
   
 	drop_invalid_header_fields = true
   }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb#drop_invalid_header_fields",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_alb", "aws_lb"},
		Base:           elb.CheckDropInvalidHeaders,
	})
}
