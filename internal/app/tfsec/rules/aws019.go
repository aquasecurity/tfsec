package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSNoKMSAutoRotate = "AWS019"
const AWSNoKMSAutoRotateDescription = "A KMS key is not configured to auto-rotate."
const AWSNoKMSAutoRotateImpact = "Long life KMS keys increase the attack surface when compromised"
const AWSNoKMSAutoRotateResolution = "Configure KMS key to auto rotate"
const AWSNoKMSAutoRotateExplanation = `
You should configure your KMS keys to auto rotate to maintain security and defend against compromise.
`
const AWSNoKMSAutoRotateBadExample = `
resource "aws_kms_key" "bad_example" {
	enable_key_rotation = false
}
`
const AWSNoKMSAutoRotateGoodExample = `
resource "aws_kms_key" "good_example" {
	enable_key_rotation = true
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSNoKMSAutoRotate,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSNoKMSAutoRotateDescription,
			Impact:      AWSNoKMSAutoRotateImpact,
			Resolution:  AWSNoKMSAutoRotateResolution,
			Explanation: AWSNoKMSAutoRotateExplanation,
			BadExample:  AWSNoKMSAutoRotateBadExample,
			GoodExample: AWSNoKMSAutoRotateGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key#enable_key_rotation",
				"https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_kms_key"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			keyUsageAttr := resourceBlock.GetAttribute("key_usage")

			if keyUsageAttr != nil && keyUsageAttr.Equals("SIGN_VERIFY") {
				return
			}

			keyRotationAttr := resourceBlock.GetAttribute("enable_key_rotation")

			if keyRotationAttr == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not have KMS Key auto-rotation enabled.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			if keyRotationAttr.Type() == cty.Bool && keyRotationAttr.Value().False() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not have KMS Key auto-rotation enabled.", resourceBlock.FullName())).
						WithRange(keyRotationAttr.Range()).
						WithAttributeAnnotation(keyRotationAttr),
				)
			}

		},
	})
}
