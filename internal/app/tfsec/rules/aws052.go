package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSRDSEncryptionNotEnabled = "AWS052"
const AWSRDSEncryptionNotEnabledDescription = "RDS encryption has not been enabled at a DB Instance level."
const AWSRDSEncryptionNotEnabledImpact = "Data can be read from the RDS instances if it is compromised"
const AWSRDSEncryptionNotEnabledResolution = "Enable encryption for RDS clusters and instances"
const AWSRDSEncryptionNotEnabledExplanation = `
Encryption should be enabled for an RDS Database instances. 

When enabling encryption by setting the kms_key_id. 
`
const AWSRDSEncryptionNotEnabledBadExample = `
resource "aws_db_instance" "bad_example" {
	
}
`
const AWSRDSEncryptionNotEnabledGoodExample = `
resource "aws_db_instance" "good_example" {
	storage_encrypted  = true
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSRDSEncryptionNotEnabled,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSRDSEncryptionNotEnabledDescription,
			Impact:      AWSRDSEncryptionNotEnabledImpact,
			Resolution:  AWSRDSEncryptionNotEnabledResolution,
			Explanation: AWSRDSEncryptionNotEnabledExplanation,
			BadExample:  AWSRDSEncryptionNotEnabledBadExample,
			GoodExample: AWSRDSEncryptionNotEnabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance",
				"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_db_instance"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("storage_encrypted") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' has no storage encryption defined.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			storageEncryptedAttr := resourceBlock.GetAttribute("storage_encrypted")
			if storageEncryptedAttr.IsFalse() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' has storage encrypted set to false", resourceBlock.FullName())).
						WithRange(storageEncryptedAttr.Range()).
						WithAttributeAnnotation(storageEncryptedAttr),
				)
			}
		},
	})
}
