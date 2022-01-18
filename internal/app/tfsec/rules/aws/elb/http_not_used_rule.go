package elb

import (
	"github.com/aquasecurity/defsec/rules/aws/elb"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS004",
		BadExample: []string{`
 resource "aws_lb_listener" "bad_example" {
 	protocol = "HTTP"
 }
 `},
		GoodExample: []string{`
 resource "aws_lb_listener" "good_example" {
 	protocol = "HTTPS"
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_lb_listener"},
		Base:           elb.CheckHttpNotUsed,
	})
}
