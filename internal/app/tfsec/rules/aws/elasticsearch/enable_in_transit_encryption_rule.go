package elasticsearch

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS032",
		Service:   "elastic-search",
		ShortCode: "enable-in-transit-encryption",
		Documentation: rule.RuleDocumentation{
			Summary:    "Elasticsearch domain uses plaintext traffic for node to node communication.",
			Impact:     "In transit data between nodes could be read if intercepted",
			Resolution: "Enable encrypted node to node communication",
			Explanation: `
Traffic flowing between Elasticsearch nodes should be encrypted to ensure sensitive data is kept private.
`,
			BadExample: []string{`
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name = "domain-foo"

  node_to_node_encryption {
    enabled = false
  }
}
`},
			GoodExample: []string{`
resource "aws_elasticsearch_domain" "good_example" {
  domain_name = "domain-foo"

  node_to_node_encryption {
    enabled = true
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#encrypt_at_rest",
				"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_elasticsearch_domain"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context block.Module) {

			encryptionBlock := resourceBlock.GetBlock("node_to_node_encryption")
			if encryptionBlock.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines an Elasticsearch domain with plaintext traffic (missing node_to_node_encryption block).", resourceBlock.FullName())
				return
			}

			enabledAttr := encryptionBlock.GetAttribute("enabled")
			if enabledAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines an Elasticsearch domain with plaintext traffic (missing enabled attribute).", resourceBlock.FullName())
				return
			}

			if enabledAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' defines an Elasticsearch domain with plaintext traffic (enabled attribute set to false).", resourceBlock.FullName()).
					WithAttribute(enabledAttr)
			}

		},
	})
}
