package rules

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

const AWSUnencryptedKinesisStream = "AWS024"
const AWSUnencryptedKinesisStreamDescription = "Kinesis stream is unencrypted."
const AWSUnencryptedKinesisStreamImpact = "Intercepted data can be read in transit"
const AWSUnencryptedKinesisStreamResolution = "Enable in transit encryption"
const AWSUnencryptedKinesisStreamExplanation = `
Kinesis streams should be encrypted to ensure sensitive data is kept private. Additionally, non-default KMS keys should be used so granularity of access control can be ensured.
`
const AWSUnencryptedKinesisStreamBadExample = `
resource "aws_kinesis_stream" "bad_example" {
	encryption_type = "NONE"
}
`
const AWSUnencryptedKinesisStreamGoodExample = `
resource "aws_kinesis_stream" "good_example" {
	encryption_type = "KMS"
	kms_key_id = "my/special/key"
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSUnencryptedKinesisStream,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSUnencryptedKinesisStreamDescription,
			Impact:      AWSUnencryptedKinesisStreamImpact,
			Resolution:  AWSUnencryptedKinesisStreamResolution,
			Explanation: AWSUnencryptedKinesisStreamExplanation,
			BadExample:  AWSUnencryptedKinesisStreamBadExample,
			GoodExample: AWSUnencryptedKinesisStreamGoodExample,
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
