package ec2

import (
	"fmt"

	"github.com/aquasecurity/defsec/infra"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/result"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
)

var CheckIMDSAccessRequiresToken = rules.RuleDef{

	Provider:   provider.AWSProvider,
	Service:    "ec2",
	ShortCode:  "enforce-http-token-imds",
	Summary:    "aws_instance should activate session tokens for Instance Metadata Service.",
	Impact:     "Instance metadata service can be interacted with freely",
	Resolution: "Enable HTTP token requirement for IMDS",
	Explanation: `
IMDS v2 (Instance Metadata Service) introduced session authentication tokens which improve security when talking to IMDS.
By default <code>aws_instance</code> resource sets IMDS session auth tokens to be optional. 
To fully protect IMDS you need to enable session tokens by using <code>metadata_options</code> block and its <code>http_tokens</code> variable set to <code>required</code>.
`,

	Links: []string{
		"https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service",
	},

	Severity: severity.High,
	CheckFunc: func(context *infra.Context) []*result.Result {

		var results []*result.Result
		for _, instance := range context.AWS.EC2.Instances {
			if !instance.RequiresIMDSToken() && !instance.HasHTTPEndpointDisabled() {
				results = append(results, &result.Result{
					Description: fmt.Sprintf("Instance '%s' does not require IMDS access to require a token", instance.Reference),
					Location:    instance.MetadataOptions.HttpTokens.Range,
				})
			}
		}
		return results
	},
}
