package elb

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
		LegacyID:  "AWS083",
		Service:   "elb",
		ShortCode: "drop-invalid-headers",
		Documentation: rule.RuleDocumentation{
			Summary: "Load balancers should drop invalid headers",
			Explanation: `
Passing unknown or invalid headers through to the target poses a potential risk of compromise. 

By setting drop_invalid_header_fields to true, anything that doe not conform to well known, defined headers will be removed by the load balancer.
`,
			Impact:     "Invalid headers being passed through to the target of the load balance may exploit vulnerabilities",
			Resolution: "Set drop_invalid_header_fields to true",
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
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_alb", "aws_lb"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.GetAttribute("load_balancer_type").IsNil() {
				return
			}

			if resourceBlock.GetAttribute("load_balancer_type").Equals("application", block.IgnoreCase) {
				if resourceBlock.MissingChild("drop_invalid_header_fields") {
					set.AddResult().
						WithDescription("Resource '%s' does not drop invalid header fields", resourceBlock.FullName())
					return
				}

				attr := resourceBlock.GetAttribute("drop_invalid_header_fields")
				if attr.IsFalse() {
					set.AddResult().
						WithDescription("Resource '%s' sets the drop_invalid_header_fields to false", resourceBlock.FullName()).
						WithAttribute(attr)
				}

			}
		},
	})
}
