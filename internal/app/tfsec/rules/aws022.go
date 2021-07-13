package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

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
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_msk_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context *hclcontext.Context) {

			defaultBehaviorBlock := resourceBlock.GetBlock("encryption_info")
			if defaultBehaviorBlock == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit (missing encryption_info block).", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			encryptionInTransit := defaultBehaviorBlock.GetBlock("encryption_in_transit")
			if encryptionInTransit == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit (missing encryption_in_transit block).", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			clientBrokerAttr := encryptionInTransit.GetAttribute("client_broker")
			if clientBrokerAttr == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit (missing client_broker block).", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			} else if clientBrokerAttr.Value().AsString() == "PLAINTEXT" {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a MSK cluster that only allows plaintext data in transit.", resourceBlock.FullName())).
						WithRange(clientBrokerAttr.Range()).
						WithAttributeAnnotation(clientBrokerAttr),
				)
			} else if clientBrokerAttr.Value().AsString() == "TLS_PLAINTEXT" {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit.", resourceBlock.FullName())).
						WithRange(clientBrokerAttr.Range()).
						WithAttributeAnnotation(clientBrokerAttr),
				)
			}
		},
	})
}
