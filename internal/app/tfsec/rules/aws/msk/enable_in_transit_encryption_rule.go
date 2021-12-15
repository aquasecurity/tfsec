package msk

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS022",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_msk_cluster"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			defaultBehaviorBlock := resourceBlock.GetBlock("encryption_info")
			if defaultBehaviorBlock.IsNil() {
				results.Add("Resource defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit (missing encryption_info block).", ?)
				return
			}

			encryptionInTransit := defaultBehaviorBlock.GetBlock("encryption_in_transit")
			if encryptionInTransit.IsNil() {
				results.Add("Resource defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit (missing encryption_in_transit block).", ?)
				return
			}

			clientBrokerAttr := encryptionInTransit.GetAttribute("client_broker")
			if clientBrokerAttr.IsNil() {
				results.Add("Resource defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit (missing client_broker block).", ?)
			} else if clientBrokerAttr.Value().AsString() == "PLAINTEXT" {
				results.Add("Resource defines a MSK cluster that only allows plaintext data in transit.", ?)
			} else if clientBrokerAttr.Value().AsString() == "TLS_PLAINTEXT" {
				results.Add("Resource defines a MSK cluster that allows plaintext as well as TLS encrypted data in transit.", ?)
			}
			return results
		},
	})
}
