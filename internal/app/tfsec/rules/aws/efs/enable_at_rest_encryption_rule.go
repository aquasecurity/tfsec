package efs

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/efs"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS048",
		BadExample: []string{`
 resource "aws_efs_file_system" "bad_example" {
   name       = "bar"
   encrypted  = false
   kms_key_id = ""
 }`},
		GoodExample: []string{`
 resource "aws_efs_file_system" "good_example" {
   name       = "bar"
   encrypted  = true
   kms_key_id = "my_kms_key"
 }`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_file_system",
			"https://docs.aws.amazon.com/efs/latest/ug/encryption.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_efs_file_system"},
		Base:           efs.CheckEnableAtRestEncryption,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			efsEnabledAttr := resourceBlock.GetAttribute("encrypted")
			if efsEnabledAttr.IsNil() {
				results.Add("Resource does not specify if encryption should be used.", resourceBlock)
				return
			}

			if efsEnabledAttr.IsFalse() {
				results.Add("Resource actively does not have encryption applied.", efsEnabledAttr)
			}

			return results
		},
	})
}
