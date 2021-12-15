package sns

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/zclconf/go-cty/cty"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
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
			"https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_sns_topic"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			kmsKeyIDAttr := resourceBlock.GetAttribute("kms_master_key_id")
			if kmsKeyIDAttr.IsNil() {
				results.Add("Resource defines an unencrypted SNS topic.", ?)
				return
			} else if kmsKeyIDAttr.Type() == cty.String && kmsKeyIDAttr.Value().AsString() == "" {
				results.Add("Resource defines an unencrypted SNS topic.", ?)
				return
			}

			if kmsKeyIDAttr.IsDataBlockReference() {

				kmsData, err := module.GetReferencedBlock(kmsKeyIDAttr, resourceBlock)
				if err != nil {
					return
				}

				keyIdAttr := kmsData.GetAttribute("key_id")
				if keyIdAttr.IsNotNil() && keyIdAttr.Equals("alias/aws/sns") {
					results.Add("Resource explicitly uses the default CMK", ?)
				}

			}

			return results
		},
	})
}
