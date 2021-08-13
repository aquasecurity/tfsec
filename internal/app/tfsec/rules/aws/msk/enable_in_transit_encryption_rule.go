package msk

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
		LegacyID:  "AWS022",
		Service:   "msk",
		ShortCode: "enable-in-transit-encryption",
		Documentation: rule.RuleDocumentation{
			Summary:    "A MSK cluster allows unencrypted data in transit.",
			Impact:     "Intercepted data can be read in transit",
			Resolution: "Enable in transit encryption",
			Explanation: `
Encryption should be forced for Kafka clusters, including for communication between nodes. This ensure sensitive data is kept private.
`,
			BadExample: []string{`
resource "aws_msk_cluster" "bad_example" {
	encryption_info {
		encryption_in_transit {
			client_broker = "TLS_PLAINTEXT"
			in_cluster = true
		}
	}
}
`},
			GoodExample: []string{`
resource "aws_msk_cluster" "good_example" {
	encryption_info {
		encryption_in_transit {
			client_broker = "TLS"
			in_cluster = true
		}
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#encryption_info-argument-reference",
				"https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_msk_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context block.Module) {

			defaultBehaviorBlock := resourceBlock.GetBlock("encryption_info")
			if defaultBehaviorBlock.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit (missing encryption_info block).", resourceBlock.FullName())
				return
			}

			encryptionInTransit := defaultBehaviorBlock.GetBlock("encryption_in_transit")
			if encryptionInTransit.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit (missing encryption_in_transit block).", resourceBlock.FullName()).WithBlock(defaultBehaviorBlock)
				return
			}

			clientBrokerAttr := encryptionInTransit.GetAttribute("client_broker")
			if clientBrokerAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit (missing client_broker block).", resourceBlock.FullName()).WithBlock(encryptionInTransit)
			} else if clientBrokerAttr.Value().AsString() == "PLAINTEXT" {
				set.AddResult().
					WithDescription("Resource '%s' defines a MSK cluster that only allows plaintext data in transit.", resourceBlock.FullName()).
					WithAttribute(clientBrokerAttr)
			} else if clientBrokerAttr.Value().AsString() == "TLS_PLAINTEXT" {
				set.AddResult().
					WithDescription("Resource '%s' defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit.", resourceBlock.FullName()).
					WithAttribute(clientBrokerAttr)
			}
		},
	})
}
