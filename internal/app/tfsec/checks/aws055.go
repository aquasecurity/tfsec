package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSElasticSearchNodeToNodeEncryption scanner.RuleCode = "AWS055"
const AWSElasticSearchNodeToNodeEncryptionDescription scanner.RuleSummary = "ElasticSearch nodes should communicate with node to node encryption enabled."
const AWSElasticSearchNodeToNodeEncryptionExplanation = `
Node-to-node encryption provides an additional layer of security on top of the default features of Amazon ES.

By default, domains do not use node-to-node encryption, and you can't configure existing domains to use the feature.

Node-to-node encryption enables TLS 1.2 encryption for all communications within the VPC.
`
const AWSElasticSearchNodeToNodeEncryptionBadExample = `
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  domain_endpoint_options {
    enforce_https = false
  }
}

resource "aws_elasticsearch_domain" "bad_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  domain_endpoint_options {
    enforce_https = false
  }

  node_to_node_encryption {
    enabled = false
  }
}
`
const AWSElasticSearchNodeToNodeEncryptionGoodExample = `
resource "aws_elasticsearch_domain" "good_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  domain_endpoint_options {
    enforce_https = false
  }

  node_to_node_encryption {
    enabled = true
  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSElasticSearchNodeToNodeEncryption,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSElasticSearchNodeToNodeEncryptionDescription,
			Explanation: AWSElasticSearchNodeToNodeEncryptionExplanation,
			BadExample:  AWSElasticSearchNodeToNodeEncryptionBadExample,
			GoodExample: AWSElasticSearchNodeToNodeEncryptionGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain",
				"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticsearch_domain"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if block.MissingChild("node_to_node_encryption") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not configure node to node encryption on the domain.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			node2nodeEncryption := block.GetBlock("node_to_node_encryption")
			enabled := node2nodeEncryption.GetAttribute("enabled")

			if enabled == nil || enabled.IsFalse() {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' explicitly disables node to node encryption on the domain.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
