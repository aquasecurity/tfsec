package kinesis

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS024",
		Service:   "kinesis",
		ShortCode: "enable-in-transit-encryption",
		Documentation: rule.RuleDocumentation{
			Summary:    "Kinesis stream is unencrypted.",
			Impact:     "Intercepted data can be read in transit",
			Resolution: "Enable in transit encryption",
			Explanation: `
Kinesis streams should be encrypted to ensure sensitive data is kept private. Additionally, non-default KMS keys should be used so granularity of access control can be ensured.
`,
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
				"https://docs.aws.amazon.com/streams/latest/dev/server-side-encryption.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_kinesis_stream"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context *hclcontext.Context) {

			encryptionTypeAttr := resourceBlock.GetAttribute("encryption_type")
			if encryptionTypeAttr == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines an unencrypted Kinesis Stream.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			} else if encryptionTypeAttr.Type() == cty.String && strings.ToUpper(encryptionTypeAttr.Value().AsString()) != "KMS" {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines an unencrypted Kinesis Stream.", resourceBlock.FullName())).
						WithRange(encryptionTypeAttr.Range()).
						WithAttributeAnnotation(encryptionTypeAttr),
				)
			} else {
				keyIDAttr := resourceBlock.GetAttribute("kms_key_id")
				if keyIDAttr == nil || keyIDAttr.IsEmpty() || keyIDAttr.Equals("alias/aws/kinesis") {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' defines a Kinesis Stream encrypted with the default Kinesis key.", resourceBlock.FullName())).
							WithRange(resourceBlock.Range()),
					)
				}
			}
		},
	})
}
