package elb

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/elb"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
			"https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_alb", "aws_lb"},
		Base:           elb.CheckDropInvalidHeaders,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.GetAttribute("load_balancer_type").IsNil() {
				return
			}

			if resourceBlock.GetAttribute("load_balancer_type").Equals("application", block.IgnoreCase) {
				if resourceBlock.MissingChild("drop_invalid_header_fields") {
					results.Add("Resource does not drop invalid header fields", resourceBlock)
					return
				}

				attr := resourceBlock.GetAttribute("drop_invalid_header_fields")
				if attr.IsFalse() {
					results.Add("Resource sets the drop_invalid_header_fields to false", attr)
				}

			}
			return results
		},
	})
}
