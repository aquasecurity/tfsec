package sns

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS016",
		Service:   "sns",
		ShortCode: "enable-topic-encryption",
		Documentation: rule.RuleDocumentation{
			Summary:    "Unencrypted SNS topic.",
			Impact:     "The SNS topic messages could be read if compromised",
			Resolution: "Turn on SNS Topic encryption",
			Explanation: `
Queues should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific queues.
`,
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
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_sns_topic"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {

			kmsKeyIDAttr := resourceBlock.GetAttribute("kms_master_key_id")
			if kmsKeyIDAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted SNS topic.", resourceBlock.FullName())
				return
			} else if kmsKeyIDAttr.Type() == cty.String && kmsKeyIDAttr.Value().AsString() == "" {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted SNS topic.", resourceBlock.FullName()).
					WithAttribute(kmsKeyIDAttr)
				return
			}

			if kmsKeyIDAttr.IsDataBlockReference() {

				kmsData, err := module.GetReferencedBlock(kmsKeyIDAttr)
				if err != nil {
					return
				}

				keyIdAttr := kmsData.GetAttribute("key_id")
				if keyIdAttr.IsNotNil() && keyIdAttr.Equals("alias/aws/sns") {
					set.AddResult().
						WithDescription("Resource '%s' explicitly uses the default CMK", resourceBlock.FullName()).
						WithAttribute(kmsKeyIDAttr)
				}

			}

		},
	})
}
