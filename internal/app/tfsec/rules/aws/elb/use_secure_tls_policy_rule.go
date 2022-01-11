package elb

import (
	"github.com/aquasecurity/defsec/rules/aws/elb"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

var outdatedSSLPolicies = []string{
	"ELBSecurityPolicy-2015-05",
	"ELBSecurityPolicy-TLS-1-0-2015-04",
	"ELBSecurityPolicy-2016-08",
	"ELBSecurityPolicy-TLS-1-1-2017-01",
}

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS010",
		BadExample: []string{`
 resource "aws_alb" "front_end" {
 }

 resource "aws_alb_listener" "bad_example" {
	load_balancer_arn = aws_alb.front_end.arn
 	ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"
 	protocol = "HTTPS"
 }
 `},
		GoodExample: []string{`
 resource "aws_alb" "front_end" {
 }

 resource "aws_alb_listener" "good_example" {
	load_balancer_arn = aws_alb.front_end.arn
 	ssl_policy = "ELBSecurityPolicy-TLS-1-2-2017-01"
 	protocol = "HTTPS"
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_lb_listener", "aws_alb_listener"},
		Base:           elb.CheckUseSecureTlsPolicy,
	})
}
