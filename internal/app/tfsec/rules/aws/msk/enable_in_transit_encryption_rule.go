package msk

import (
	"github.com/aquasecurity/defsec/rules/aws/msk"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
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
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_msk_cluster"},
		Base:           msk.CheckEnableInTransitEncryption,
	})
}
