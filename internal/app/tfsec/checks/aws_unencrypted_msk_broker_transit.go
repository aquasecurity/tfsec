package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSUnencryptedMSKBroker See https://github.com/tfsec/tfsec#included-checks for check info
const AWSUnencryptedMSKBroker scanner.RuleID = "AWS022"
const AWSUnencryptedMSKBrokerDescription scanner.RuleDescription = "A MSK cluster allows unencrypted data in transit."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSUnencryptedMSKBroker,
		Description:    AWSUnencryptedMSKBrokerDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_msk_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			var results []scanner.Result

			defaultBehaviorBlock := block.GetBlock("encryption_info")
			if defaultBehaviorBlock == nil {
				results = append(results,
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit (missing encryption_info block).", block.Name()),
						block.Range(),
						scanner.SeverityWarning,
					),
				)
			} else if defaultBehaviorBlock != nil {
				encryptionInTransit := defaultBehaviorBlock.GetBlock("encryption_in_transit")
				if encryptionInTransit == nil {
					results = append(results,
						check.NewResult(
							fmt.Sprintf("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit (missing encryption_in_transit block).", block.Name()),
							block.Range(),
							scanner.SeverityWarning,
						),
					)
				} else {
					clientBroker := encryptionInTransit.GetAttribute("client_broker")
					if clientBroker == nil {
						results = append(results,
							check.NewResult(
								fmt.Sprintf("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit (missing client_broker block).", block.Name()),
								block.Range(),
								scanner.SeverityWarning,
							),
						)
					} else if clientBroker != nil && clientBroker.Value().AsString() == "PLAINTEXT" {
						results = append(results,
							check.NewResultWithValueAnnotation(
								fmt.Sprintf("Resource '%s' defines a MSK cluster that only allows plaintext data in transit.", block.Name()),
								clientBroker.Range(),
								clientBroker,
								scanner.SeverityError,
							),
						)
					} else if clientBroker != nil && clientBroker.Value().AsString() == "TLS_PLAINTEXT" {
						results = append(results,
							check.NewResultWithValueAnnotation(
								fmt.Sprintf("Resource '%s' defines a MSK cluster  that allows plaintext as well as TLS encrypted data in transit.", block.Name()),
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
