package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSInstanceMetadataChec = "AWS079"
const AWSInstanceMetadataChecDescription = "aws_instance should activate session tokens for Instance Metadata Service."
const AWSInstanceMetadataChecImpact = "Instance metadata service can be interacted with freely"
const AWSInstanceMetadataChecResolution = "Enable HTTP token requirement for IMDS"
const AWSInstanceMetadataChecExplanation = `
IMDS v2 (Instance Metadata Service) introduced session authentication tokens which improve security when talking to IMDS.
By default <code>aws_instance</code> resource sets IMDS session auth tokens to be optional. 
To fully protect IMDS you need to enable session tokens by using <code>metadata_options</code> block and its <code>http_tokens</code> variable set to <code>required</code>.
`
const AWSInstanceMetadataChecBadExample = `
resource "aws_instance" "bad_example" {
  ami           = "ami-005e54dee72cc1d00"
  instance_type = "t2.micro"
}
`
const AWSInstanceMetadataChecGoodExample = `
resource "aws_instance" "good_example" {
  ami           = "ami-005e54dee72cc1d00"
  instance_type = "t2.micro"
  metadata_options {
	http_tokens = "required"
  }	
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSInstanceMetadataChec,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSInstanceMetadataChecDescription,
			Impact:      AWSInstanceMetadataChecImpact,
			Resolution:  AWSInstanceMetadataChecResolution,
			Explanation: AWSInstanceMetadataChecExplanation,
			BadExample:  AWSInstanceMetadataChecBadExample,
			GoodExample: AWSInstanceMetadataChecGoodExample,
			Links: []string{
				"https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#metadata-options",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_instance"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			metaDataOptions := resourceBlock.GetBlock("metadata_options")
			if metaDataOptions == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' is missing `metadata_options` block - it is required with `http_tokens` set to `required` to make Instance Metadata Service more secure.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			httpEndpointAttr := metaDataOptions.GetAttribute("http_endpoint")
			if httpEndpointAttr != nil {
				if httpEndpointAttr.Equals("disabled") {
					// IMDS disabled and we don't need to check if http_tokens are correctly set up
					return
				}
			}

			httpTokensAttr := metaDataOptions.GetAttribute("http_tokens")
			if httpTokensAttr != nil {
				if !httpTokensAttr.Equals("required") {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' `metadata_options` `http_tokens` attribute - should be set to `required` to make Instance Metadata Service more secure.", resourceBlock.FullName())).
							WithRange(httpTokensAttr.Range()),
					)
				}
			}

		},
	})
}
