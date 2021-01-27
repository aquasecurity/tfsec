package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const AWSUnencryptedElasticsearchDomain scanner.RuleCode = "AWS031"
const AWSUnencryptedElasticsearchDomainDescription scanner.RuleSummary = "Elasticsearch domain isn't encrypted at rest."
const AWSUnencryptedElasticsearchDomainExplanation = `
You should ensure your Elasticsearch data is encrypted at rest to help prevent sensitive information from being read by unauthorised users. 
`
const AWSUnencryptedElasticsearchDomainBadExample = `
resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
  domain_name = "domain-foo"

  encrypt_at_rest {
    enabled = false
  }
}
`
const AWSUnencryptedElasticsearchDomainGoodExample = `
resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
  domain_name = "domain-foo"

  encrypt_at_rest {
    enabled = true
  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSUnencryptedElasticsearchDomain,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSUnencryptedElasticsearchDomainDescription,
			Explanation: AWSUnencryptedElasticsearchDomainExplanation,
			BadExample:  AWSUnencryptedElasticsearchDomainBadExample,
			GoodExample: AWSUnencryptedElasticsearchDomainGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticsearch_domain"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			encryptionBlock := block.GetBlock("encrypt_at_rest")
			if encryptionBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted Elasticsearch domain (missing encrypt_at_rest block).", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			enabledAttr := encryptionBlock.GetAttribute("enabled")
			if enabledAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted Elasticsearch domain (missing enabled attribute).", block.FullName()),
						encryptionBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			isTrueBool := enabledAttr.Type() == cty.Bool && enabledAttr.Value().True()
			isTrueString := enabledAttr.Type() == cty.String &&
				enabledAttr.Value().Equals(cty.StringVal("true")).True()
			encryptionEnabled := isTrueBool || isTrueString
			if !encryptionEnabled {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted Elasticsearch domain (enabled attribute set to false).", block.FullName()),
						encryptionBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
