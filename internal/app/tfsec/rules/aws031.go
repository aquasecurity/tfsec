package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSUnencryptedElasticsearchDomain = "AWS031"
const AWSUnencryptedElasticsearchDomainDescription = "Elasticsearch domain isn't encrypted at rest."
const AWSUnencryptedElasticsearchDomainImpact = "Data will be readable if compromised"
const AWSUnencryptedElasticsearchDomainResolution = "Enable ElasticSearch domain encryption"
const AWSUnencryptedElasticsearchDomainExplanation = `
You should ensure your Elasticsearch data is encrypted at rest to help prevent sensitive information from being read by unauthorised users. 
`
const AWSUnencryptedElasticsearchDomainBadExample = `
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name = "domain-foo"

  encrypt_at_rest {
    enabled = false
  }
}
`
const AWSUnencryptedElasticsearchDomainGoodExample = `
resource "aws_elasticsearch_domain" "good_example" {
  domain_name = "domain-foo"

  encrypt_at_rest {
    enabled = true
  }
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSUnencryptedElasticsearchDomain,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSUnencryptedElasticsearchDomainDescription,
			Impact:      AWSUnencryptedElasticsearchDomainImpact,
			Resolution:  AWSUnencryptedElasticsearchDomainResolution,
			Explanation: AWSUnencryptedElasticsearchDomainExplanation,
			BadExample:  AWSUnencryptedElasticsearchDomainBadExample,
			GoodExample: AWSUnencryptedElasticsearchDomainGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#encrypt_at_rest",
				"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html",
			},
		},
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticsearch_domain"},
		CheckFunc: func(block *block.Block, context *hclcontext.Context) []result.Result {

			encryptionBlock := block.GetBlock("encrypt_at_rest")
			if encryptionBlock == nil {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' defines an unencrypted Elasticsearch domain (missing encrypt_at_rest block).", block.FullName()),
						).WithRange(block.Range()).WithSeverity(
						severity.Error,
					),
				}
			}

			enabledAttr := encryptionBlock.GetAttribute("enabled")
			if enabledAttr == nil {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' defines an unencrypted Elasticsearch domain (missing enabled attribute).", block.FullName()),
						encryption).WithRange(block.Range()).WithSeverity(
						severity.Error,
					),
				}
			}

			isTrueBool := enabledAttr.Type() == cty.Bool && enabledAttr.Value().True()
			isTrueString := enabledAttr.Type() == cty.String &&
				enabledAttr.Value().Equals(cty.StringVal("true")).True()
			encryptionEnabled := isTrueBool || isTrueString
			if !encryptionEnabled {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' defines an unencrypted Elasticsearch domain (enabled attribute set to false).", block.FullName()),
						encryption).WithRange(block.Range()).WithSeverity(
						severity.Error,
					),
				}
			}

			return nil
		},
	})
}
