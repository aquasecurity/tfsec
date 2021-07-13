package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

const DIGLoadBalancerWithPlainHTTP = "DIG004"
const DIGLoadBalancerWithPlainHTTPDescription = "The load balancer forwarding rule is using an insecure protocol as an entrypoint"
const DIGLoadBalancerWithPlainHTTPImpact = "Your inbound traffic is not protected"
const DIGLoadBalancerWithPlainHTTPResolution = "Switch to HTTPS to benefit from TLS security features"
const DIGLoadBalancerWithPlainHTTPExplanation = `
Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.
`
const DIGLoadBalancerWithPlainHTTPBadExample = `
resource "digitalocean_loadbalancer" "bad_example" {
  name   = "bad_example-1"
  region = "nyc3"

  forwarding_rule {
    entry_port     = 80
    entry_protocol = "http"

    target_port     = 80
    target_protocol = "http"
  }

  droplet_ids = [digitalocean_droplet.web.id]
}
`
const DIGLoadBalancerWithPlainHTTPGoodExample = `
resource "digitalocean_loadbalancer" "bad_example" {
  name   = "bad_example-1"
  region = "nyc3"
  
  forwarding_rule {
	entry_port     = 443
	entry_protocol = "https"
  
	target_port     = 443
	target_protocol = "https"
  }
  
  droplet_ids = [digitalocean_droplet.web.id]
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: DIGLoadBalancerWithPlainHTTP,
		Documentation: rule.RuleDocumentation{
			Summary:     DIGLoadBalancerWithPlainHTTPDescription,
			Explanation: DIGLoadBalancerWithPlainHTTPExplanation,
			Impact:      DIGLoadBalancerWithPlainHTTPImpact,
			Resolution:  DIGLoadBalancerWithPlainHTTPResolution,
			BadExample:  DIGLoadBalancerWithPlainHTTPBadExample,
			GoodExample: DIGLoadBalancerWithPlainHTTPGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/loadbalancer",
				"https://docs.digitalocean.com/products/networking/load-balancers/",
			},
		},
		Provider:        provider.DigitalOceanProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"digitalocean_loadbalancer"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("forwarding_rule") {
				return
			}

			forwardingRules := resourceBlock.GetBlocks("forwarding_rule")
			for _, rule := range forwardingRules {
				if rule.MissingChild("entry_protocol") {
					continue
				}
				entryPointAttr := rule.GetAttribute("entry_protocol")
				if entryPointAttr.Equals("http", block.IgnoreCase) {
					set.Add(result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' uses plain HTTP instead of HTTPS.", resourceBlock.FullName())).
						WithAttributeAnnotation(entryPointAttr).
						WithRange(entryPointAttr.Range()))
				}
			}
		},
	})
}
