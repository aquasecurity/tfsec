package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSALBDropsInvalidHeaders scanner.RuleCode = "AWS083"
const AWSALBDropsInvalidHeadersDescription scanner.RuleSummary = "Load balancers should drop invalid headers"
const AWSALBDropsInvalidHeadersImpact = "Invalid headers being passed through to the target of the load balance may exploit vulnerabilities"
const AWSALBDropsInvalidHeadersResolution = "Set drop_invalid_header_fields to true"
const AWSALBDropsInvalidHeadersExplanation = `
Passing unknown or invalid headers through to the target poses a potential risk of compromise. 

By setting drop_invalid_header_fields to true, anything that doe not conform to well known, defined headers will be removed by the load balancer.
`
const AWSALBDropsInvalidHeadersBadExample = `
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
`
const AWSALBDropsInvalidHeadersGoodExample = `
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
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSALBDropsInvalidHeaders,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSALBDropsInvalidHeadersDescription,
			Explanation: AWSALBDropsInvalidHeadersExplanation,
			Impact:      AWSALBDropsInvalidHeadersImpact,
			Resolution:  AWSALBDropsInvalidHeadersResolution,
			BadExample:  AWSALBDropsInvalidHeadersBadExample,
			GoodExample: AWSALBDropsInvalidHeadersGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb#drop_invalid_header_fields",
				"https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_alb", "aws_lb"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.GetAttribute("load_balancer_type").Equals("application", parser.IgnoreCase) {
				if block.MissingChild("drop_invalid_header_fields") {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' does not drop invalid header fields", block.FullName()),
							block.Range(),
							scanner.SeverityError,
						),
					}
				}

				attr := block.GetAttribute("drop_invalid_header_fields")
				if attr.IsFalse() {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' sets the drop_invalid_header_fields to false", block.FullName()),
							attr.Range(),
							attr,
							scanner.SeverityError,
						),
					}
				}

			}
			return nil
		},
	})
}
