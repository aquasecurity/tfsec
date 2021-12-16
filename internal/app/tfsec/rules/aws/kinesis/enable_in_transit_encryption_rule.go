package kinesis

import (
	"strings"

	"github.com/aquasecurity/defsec/rules/aws/kinesis"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/zclconf/go-cty/cty"
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
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			encryptionTypeAttr := resourceBlock.GetAttribute("encryption_type")
			if encryptionTypeAttr.IsNil() {
				results.Add("Resource defines an unencrypted Kinesis Stream.", resourceBlock)
			} else if encryptionTypeAttr.Type() == cty.String && strings.ToUpper(encryptionTypeAttr.Value().AsString()) != "KMS" {
				results.Add("Resource defines an unencrypted Kinesis Stream.", encryptionTypeAttr)
			} else {
				keyIDAttr := resourceBlock.GetAttribute("kms_key_id")
				if keyIDAttr.IsNil() {
					results.Add("Resource defines a Kinesis Stream encrypted with the default Kinesis key.", resourceBlock)
				} else if keyIDAttr.IsEmpty() || keyIDAttr.Equals("alias/aws/kinesis") {
					results.Add("Resource defines a Kinesis Stream encrypted with the default Kinesis key.", keyIDAttr)
				}
			}
			return results
		},
	})
}
