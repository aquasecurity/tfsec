package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSUnencryptedMSKBroker See https://github.com/tfsec/tfsec#included-checks for check info
const AWSUnencryptedMSKBroker scanner.RuleCode = "AWS022"
const AWSUnencryptedMSKBrokerDescription scanner.RuleSummary = "A MSK cluster allows unencrypted data in transit."
const AWSUnencryptedMSKBrokerExplanation = `
Encryption should be forced for Kafka clusters, including for communication between nodes. This ensure sensitive data is kept private.
`
const AWSUnencryptedMSKBrokerBadExample = `
resource "aws_msk_cluster" "msk-cluster" {
	encryption_info {
		encryption_in_transit {
			client_broker = "TLS_PLAINTEXT"
			in_cluster = true
		}
	}
}
`
const AWSUnencryptedMSKBrokerGoodExample = `
resource "aws_msk_cluster" "msk-cluster" {
	encryption_info {
		encryption_in_transit {
			client_broker = "TLS"
			in_cluster = true
		}
	}
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSUnencryptedMSKBroker,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSUnencryptedMSKBrokerDescription,
			Explanation: AWSUnencryptedMSKBrokerExplanation,
			BadExample:  AWSUnencryptedMSKBrokerBadExample,
			GoodExample: AWSUnencryptedMSKBrokerGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_msk_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			var results []scanner.Result

			defaultBehaviorBlock := block.GetBlock("encryption_info")
			if defaultBehaviorBlock == nil {
				results = append(results,
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit (missing encryption_info block).", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				)
			} else if defaultBehaviorBlock != nil {
				encryptionInTransit := defaultBehaviorBlock.GetBlock("encryption_in_transit")
				if encryptionInTransit == nil {
					results = append(results,
						check.NewResult(
							fmt.Sprintf("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit (missing encryption_in_transit block).", block.FullName()),
							block.Range(),
							scanner.SeverityWarning,
						),
					)
				} else {
					clientBroker := encryptionInTransit.GetAttribute("client_broker")
					if clientBroker == nil {
						results = append(results,
							check.NewResult(
								fmt.Sprintf("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit (missing client_broker block).", block.FullName()),
								block.Range(),
								scanner.SeverityWarning,
							),
						)
					} else if clientBroker != nil && clientBroker.Value().AsString() == "PLAINTEXT" {
						results = append(results,
							check.NewResultWithValueAnnotation(
								fmt.Sprintf("Resource '%s' defines a MSK cluster that only allows plaintext data in transit.", block.FullName()),
								clientBroker.Range(),
								clientBroker,
								scanner.SeverityError,
							),
						)
					} else if clientBroker != nil && clientBroker.Value().AsString() == "TLS_PLAINTEXT" {
						results = append(results,
							check.NewResultWithValueAnnotation(
								fmt.Sprintf("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit.", block.FullName()),
								clientBroker.Range(),
								clientBroker,
								scanner.SeverityWarning,
							),
						)
					}
				}
			}

			return results

		},
	})
}
