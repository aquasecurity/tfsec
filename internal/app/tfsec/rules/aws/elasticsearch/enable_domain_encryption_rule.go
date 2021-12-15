package elasticsearch

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/elasticsearch"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS031",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticsearch_domain"},
		Base:           elasticsearch.CheckEnableDomainEncryption,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			encryptionBlock := resourceBlock.GetBlock("encrypt_at_rest")
			if encryptionBlock.IsNil() {
				results.Add("Resource defines an unencrypted Elasticsearch domain (missing encrypt_at_rest block).", resourceBlock)
				return
			}

			enabledAttr := encryptionBlock.GetAttribute("enabled")
			if enabledAttr.IsNil() {
				results.Add("Resource defines an unencrypted Elasticsearch domain (missing enabled attribute).", encryptionBlock)
				return
			}

			if enabledAttr.IsFalse() {
				results.Add("Resource defines an unencrypted Elasticsearch domain (enabled attribute set to false).", enabledAttr)
			}

			return results
		},
	})
}
