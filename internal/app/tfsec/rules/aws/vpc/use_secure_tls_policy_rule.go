package vpc

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
 resource "aws_alb_listener" "bad_example" {
 	ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"
 	protocol = "HTTPS"
 }
 `},
		GoodExample: []string{`
 resource "aws_alb_listener" "good_example" {
 	ssl_policy = "ELBSecurityPolicy-TLS-1-2-2017-01"
 	protocol = "HTTPS"
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_lb_listener", "aws_alb_listener"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if sslPolicyAttr := resourceBlock.GetAttribute("ssl_policy"); sslPolicyAttr.IsString() {
				for _, policy := range outdatedSSLPolicies {
					if sslPolicyAttr.Equals(policy) {
						results.Add("Resource is using an outdated SSL policy.", sslPolicyAttr)
					}
				}
			}

			return results
		},
	})
}
