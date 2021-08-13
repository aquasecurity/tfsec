package elasticservice

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
		LegacyID:  "AWS031",
		Service:   "elastic-service",
		ShortCode: "enable-domain-encryption",
		Documentation: rule.RuleDocumentation{
			Summary:    "Elasticsearch domain isn't encrypted at rest.",
			Impact:     "Data will be readable if compromised",
			Resolution: "Enable ElasticSearch domain encryption",
			Explanation: `
You should ensure your Elasticsearch data is encrypted at rest to help prevent sensitive information from being read by unauthorised users. 
`,
			BadExample: []string{`
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name = "domain-foo"

  encrypt_at_rest {
    enabled = false
  }
}
`},
			GoodExample: []string{`
resource "aws_elasticsearch_domain" "good_example" {
  domain_name = "domain-foo"

  encrypt_at_rest {
    enabled = true
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#encrypt_at_rest",
				"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_elasticsearch_domain"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context block.Module) {

			encryptionBlock := resourceBlock.GetBlock("encrypt_at_rest")
			if encryptionBlock.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted Elasticsearch domain (missing encrypt_at_rest block).", resourceBlock.FullName())
				return
			}

			enabledAttr := encryptionBlock.GetAttribute("enabled")
			if enabledAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted Elasticsearch domain (missing enabled attribute).", resourceBlock.FullName())
				return
			}

			if enabledAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted Elasticsearch domain (enabled attribute set to false).", resourceBlock.FullName()).
					WithAttribute(enabledAttr)
			}
		},
	})
}
