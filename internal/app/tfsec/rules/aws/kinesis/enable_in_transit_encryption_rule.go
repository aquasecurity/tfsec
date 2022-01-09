package kinesis

import (
	"github.com/aquasecurity/defsec/rules/aws/kinesis"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS024",
		BadExample: []string{`
 resource "aws_kinesis_stream" "bad_example" {
 	encryption_type = "NONE"
 }
 `},
		GoodExample: []string{`
 resource "aws_kinesis_stream" "good_example" {
 	encryption_type = "KMS"
 	kms_key_id = "my/special/key"
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kinesis_stream#encryption_type",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_kinesis_stream"},
		Base:           kinesis.CheckEnableInTransitEncryption,
	})
}
