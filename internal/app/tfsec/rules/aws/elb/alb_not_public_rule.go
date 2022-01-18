package elb

import (
	"github.com/aquasecurity/defsec/rules/aws/elb"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS005",
		BadExample: []string{`
 resource "aws_alb" "bad_example" {
 	internal = false
 }
 `},
		GoodExample: []string{`
 resource "aws_alb" "good_example" {
 	internal = true
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_alb", "aws_elb", "aws_lb"},
		Base:           elb.CheckAlbNotPublic,
	})
}
