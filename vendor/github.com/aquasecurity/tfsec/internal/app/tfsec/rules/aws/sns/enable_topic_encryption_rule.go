package sns

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/sns"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/zclconf/go-cty/cty"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS016",
		BadExample: []string{`
 resource "aws_sns_topic" "bad_example" {
 	# no key id specified
 }
 `},
		GoodExample: []string{`
 resource "aws_sns_topic" "good_example" {
 	kms_master_key_id = "/blah"
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic#example-with-server-side-encryption-sse",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_sns_topic"},
		Base:           sns.CheckEnableTopicEncryption,
		CheckTerraform: func(resourceBlock block.Block, module block.Module) (results rules.Results) {

			kmsKeyIDAttr := resourceBlock.GetAttribute("kms_master_key_id")
			if kmsKeyIDAttr.IsNil() {
				results.Add("Resource defines an unencrypted SNS topic.", resourceBlock)
				return
			} else if kmsKeyIDAttr.Type() == cty.String && kmsKeyIDAttr.Value().AsString() == "" {
				results.Add("Resource defines an unencrypted SNS topic.", kmsKeyIDAttr)
				return
			}

			if kmsKeyIDAttr.IsDataBlockReference() {

				kmsData, err := module.GetReferencedBlock(kmsKeyIDAttr, resourceBlock)
				if err != nil {
					return
				}

				keyIdAttr := kmsData.GetAttribute("key_id")
				if keyIdAttr.IsNotNil() && keyIdAttr.Equals("alias/aws/sns") {
					results.Add("Resource explicitly uses the default CMK", keyIdAttr)
				}

			}

			return results
		},
	})
}
