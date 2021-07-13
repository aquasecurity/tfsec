package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSPlaintextNodeToNodeElasticsearchTraffic = "AWS032"
const AWSPlaintextNodeToNodeElasticsearchTrafficDescription = "Elasticsearch domain uses plaintext traffic for node to node communication."
const AWSPlaintextNodeToNodeElasticsearchTrafficImpact = "In transit data between nodes could be read if intercepted"
const AWSPlaintextNodeToNodeElasticsearchTrafficResolution = "Enable encrypted node to node communication"
const AWSPlaintextNodeToNodeElasticsearchTrafficExplanation = `
Traffic flowing between Elasticsearch nodes should be encrypted to ensure sensitive data is kept private.
`
const AWSPlaintextNodeToNodeElasticsearchTrafficBadExample = `
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name = "domain-foo"

  node_to_node_encryption {
    enabled = false
  }
}
`
const AWSPlaintextNodeToNodeElasticsearchTrafficGoodExample = `
resource "aws_elasticsearch_domain" "good_example" {
  domain_name = "domain-foo"

  node_to_node_encryption {
    enabled = true
  }
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSPlaintextNodeToNodeElasticsearchTraffic,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSPlaintextNodeToNodeElasticsearchTrafficDescription,
			Impact:      AWSPlaintextNodeToNodeElasticsearchTrafficImpact,
			Resolution:  AWSPlaintextNodeToNodeElasticsearchTrafficResolution,
			Explanation: AWSPlaintextNodeToNodeElasticsearchTrafficExplanation,
			BadExample:  AWSPlaintextNodeToNodeElasticsearchTrafficBadExample,
			GoodExample: AWSPlaintextNodeToNodeElasticsearchTrafficGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#encrypt_at_rest",
				"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_elasticsearch_domain"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context *hclcontext.Context) {

			encryptionBlock := resourceBlock.GetBlock("node_to_node_encryption")
			if encryptionBlock == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with plaintext traffic (missing node_to_node_encryption block).", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			enabledAttr := encryptionBlock.GetAttribute("enabled")
			if enabledAttr == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with plaintext traffic (missing enabled attribute).", resourceBlock.FullName())).
						WithRange(encryptionBlock.Range()),
				)
				return
			}

			isTrueBool := enabledAttr.Type() == cty.Bool && enabledAttr.Value().True()
			isTrueString := enabledAttr.Type() == cty.String &&
				enabledAttr.Value().Equals(cty.StringVal("true")).True()
			nodeToNodeEncryptionEnabled := isTrueBool || isTrueString
			if !nodeToNodeEncryptionEnabled {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with plaintext traffic (enabled attribute set to false).", resourceBlock.FullName())).
						WithRange(encryptionBlock.Range()),
				)
			}

		},
	})
}
