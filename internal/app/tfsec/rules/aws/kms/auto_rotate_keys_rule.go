package kms

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/kms"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/zclconf/go-cty/cty"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS019",
		BadExample: []string{`
 resource "aws_kms_key" "bad_example" {
 	enable_key_rotation = false
 }
 `},
		GoodExample: []string{`
 resource "aws_kms_key" "good_example" {
 	enable_key_rotation = true
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key#enable_key_rotation",
			"https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_kms_key"},
		Base:           kms.CheckAutoRotateKeys,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			keyUsageAttr := resourceBlock.GetAttribute("key_usage")

			if keyUsageAttr.IsNotNil() && keyUsageAttr.Equals("SIGN_VERIFY") {
				return
			}

			keyRotationAttr := resourceBlock.GetAttribute("enable_key_rotation")
			if keyRotationAttr.IsNil() {
				results.Add("Resource does not have KMS Key auto-rotation enabled.", resourceBlock)
				return
			}

			if keyRotationAttr.Type() == cty.Bool && keyRotationAttr.Value().False() {
				results.Add("Resource does not have KMS Key auto-rotation enabled.", keyRotationAttr)
			}

			return results
		},
	})
}
