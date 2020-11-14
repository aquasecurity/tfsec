package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSElasticSearchDataStoreEncryptedAtRest scanner.RuleCode = "AWS056"
const AWSElasticSearchDataStoreEncryptedAtRestDescription scanner.RuleSummary = "ElasticSearch data stores should be encrypted at rest."
const AWSElasticSearchDataStoreEncryptedAtRestExplanation = `
Amazon ElasticSearch domains offer encryption of data at rest, a security feature that helps prevent unauthorized access to your data. 

The feature uses AWS Key Management Service (AWS KMS) to store and manage your encryption keys and the Advanced Encryption Standard algorithm with 256-bit keys (AES-256) to perform the encryption.
`
const AWSElasticSearchDataStoreEncryptedAtRestBadExample = `
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"
}

resource "aws_elasticsearch_domain" "bad_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  encrypt_at_rest {
    enabled = false
  }
}
`
const AWSElasticSearchDataStoreEncryptedAtRestGoodExample = `
resource "aws_elasticsearch_domain" "good_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  encrypt_at_rest {
    enabled = true
  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSElasticSearchDataStoreEncryptedAtRest,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSElasticSearchDataStoreEncryptedAtRestDescription,
			Explanation: AWSElasticSearchDataStoreEncryptedAtRestExplanation,
			BadExample:  AWSElasticSearchDataStoreEncryptedAtRestBadExample,
			GoodExample: AWSElasticSearchDataStoreEncryptedAtRestGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#kms_key_id",
				"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticsearch_domain"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if block.MissingChild("encrypt_at_rest") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not configure encryption at rest on the domain.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			encryptionAtRest := block.GetBlock("encrypt_at_rest")
			enabled := encryptionAtRest.GetAttribute("enabled")

			if enabled == nil || enabled.IsFalse() {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' explicitly disables encryption at rest on the domain.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
