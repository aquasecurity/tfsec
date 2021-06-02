package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// AWSUnencryptedMSKBroker See https://github.com/tfsec/tfsec#included-checks for check info
const AWSUnencryptedMSKBroker = "AWS022"
const AWSUnencryptedMSKBrokerDescription = "A MSK cluster allows unencrypted data in transit."
const AWSUnencryptedMSKBrokerImpact = "Intercepted data can be read in transit"
const AWSUnencryptedMSKBrokerResolution = "Enable in transit encryption"
const AWSUnencryptedMSKBrokerExplanation = `
Encryption should be forced for Kafka clusters, including for communication between nodes. This ensure sensitive data is kept private.
`
const AWSUnencryptedMSKBrokerBadExample = `
resource "aws_msk_cluster" "bad_example" {
	encryption_info {
		encryption_in_transit {
			client_broker = "TLS_PLAINTEXT"
			in_cluster = true
		}
	}
}
`
const AWSUnencryptedMSKBrokerGoodExample = `
resource "aws_msk_cluster" "good_example" {
	encryption_info {
		encryption_in_transit {
			client_broker = "TLS"
			in_cluster = true
		}
	}
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSUnencryptedMSKBroker,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSUnencryptedMSKBrokerDescription,
			Impact:      AWSUnencryptedMSKBrokerImpact,
			Resolution:  AWSUnencryptedMSKBrokerResolution,
			Explanation: AWSUnencryptedMSKBrokerExplanation,
			BadExample:  AWSUnencryptedMSKBrokerBadExample,
			GoodExample: AWSUnencryptedMSKBrokerGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#encryption_info-argument-reference",
				"https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html",
			},
		},
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_msk_cluster"},
		CheckFunc: func(block *block.Block, context *hclcontext.Context) []result.Result {

			var results []result.Result

			defaultBehaviorBlock := block.GetBlock("encryption_info")
			if defaultBehaviorBlock == nil {
				results = append(results,
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit (missing encryption_info block).", block.FullName()),
					).WithRange(block.Range()).WithSeverity(
						severity.Warning,
					),
				)
			} else if defaultBehaviorBlock != nil {
				encryptionInTransit := defaultBehaviorBlock.GetBlock("encryption_in_transit")
				if encryptionInTransit == nil {
					results = append(results,
						result.New().WithDescription(
							fmt.Sprintf("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit (missing encryption_in_transit block).", block.FullName()),
						).WithRange(block.Range()).WithSeverity(
							severity.Warning,
						),
					)
				} else {
					clientBroker := encryptionInTransit.GetAttribute("client_broker")
					if clientBroker == nil {
						results = append(results,
							result.New().WithDescription(
								fmt.Sprintf("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit (missing client_broker block).", block.FullName()),
							).WithRange(block.Range()).WithSeverity(
								severity.Warning,
							),
						)
					} else if clientBroker != nil && clientBroker.Value().AsString() == "PLAINTEXT" {
						results = append(results,
							result.New().WithDescription(
								fmt.Sprintf("Resource '%s' defines a MSK cluster that only allows plaintext data in transit.", block.FullName()),
								clientBroker.Range(),
								clientBroker,
								severity.Error,
							),
						)
					} else if clientBroker != nil && clientBroker.Value().AsString() == "TLS_PLAINTEXT" {
						results = append(results,
							result.New().WithDescription(
								fmt.Sprintf("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit.", block.FullName()),
								clientBroker.Range(),
								clientBroker,
								severity.Warning,
							),
						)
					}
				}
			}

			return results

		},
	})
}
