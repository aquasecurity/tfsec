package vpc

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

var outdatedSSLPolicies = []string{
	"ELBSecurityPolicy-2015-05",
	"ELBSecurityPolicy-TLS-1-0-2015-04",
	"ELBSecurityPolicy-2016-08",
	"ELBSecurityPolicy-TLS-1-1-2017-01",
}

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS010",
		Service:   "vpc",
		ShortCode: "use-secure-tls-policy",
		Documentation: rule.RuleDocumentation{
			Summary:    "An outdated SSL policy is in use by a load balancer.",
			Impact:     "The SSL policy is outdated and has known vulnerabilities",
			Resolution: "Use a more recent TLS/SSL policy for the load balancer",
			Explanation: `
You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+. 
`,
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
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_lb_listener", "aws_alb_listener"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if sslPolicyAttr := resourceBlock.GetAttribute("ssl_policy"); sslPolicyAttr != nil && sslPolicyAttr.Type() == cty.String {
				for _, policy := range outdatedSSLPolicies {
					if policy == sslPolicyAttr.Value().AsString() {
						set.Add(
							result.New(resourceBlock).
								WithDescription(fmt.Sprintf("Resource '%s' is using an outdated SSL policy.", resourceBlock.FullName())).
								WithAttribute(sslPolicyAttr),
						)
					}
				}
			}

		},
	})
}
