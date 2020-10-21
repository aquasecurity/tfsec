package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSPlaintextNodeToNodeElasticsearchTraffic See https://github.com/tfsec/tfsec#included-checks for check info
const AWSPlaintextNodeToNodeElasticsearchTraffic scanner.RuleCode = "AWS032"
const AWSPlaintextNodeToNodeElasticsearchTrafficDescription scanner.RuleSummary = "Elasticsearch domain uses plaintext traffic for node to node communication."
const AWSPlaintextNodeToNodeElasticsearchTrafficExplanation = `
Traffic flowing between Elasticsearch nodes should be encrypted to ensure sensitive data is kept private.
`
const AWSPlaintextNodeToNodeElasticsearchTrafficBadExample = `
resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
  domain_name = "domain-foo"

  node_to_node_encryption {
    enabled = false
  }
}
`
const AWSPlaintextNodeToNodeElasticsearchTrafficGoodExample = `
resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
  domain_name = "domain-foo"

  node_to_node_encryption {
    enabled = true
  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSPlaintextNodeToNodeElasticsearchTraffic,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSPlaintextNodeToNodeElasticsearchTrafficDescription,
			Explanation: AWSPlaintextNodeToNodeElasticsearchTrafficExplanation,
			BadExample:  AWSPlaintextNodeToNodeElasticsearchTrafficBadExample,
			GoodExample: AWSPlaintextNodeToNodeElasticsearchTrafficGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticsearch_domain"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			encryptionBlock := block.GetBlock("node_to_node_encryption")
			if encryptionBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with plaintext traffic (missing node_to_node_encryption block).", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			enabledAttr := encryptionBlock.GetAttribute("enabled")
			if enabledAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with plaintext traffic (missing enabled attribute).", block.FullName()),
						encryptionBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			isTrueBool := enabledAttr.Type() == cty.Bool && enabledAttr.Value().True()
			isTrueString := enabledAttr.Type() == cty.String &&
				enabledAttr.Value().Equals(cty.StringVal("true")).True()
			nodeToNodeEncryptionEnabled := isTrueBool || isTrueString
			if !nodeToNodeEncryptionEnabled {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with plaintext traffic (enabled attribute set to false).", block.FullName()),
						encryptionBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
