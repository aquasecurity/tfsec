package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
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
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_instance"},
		CheckFunc: func(set result.Set, block *block.Block, _ *hclcontext.Context) {

			if block.MissingChild("storage_encrypted") {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' has no storage encryption defined.", block.FullName()),
						).WithRange(block.Range()).WithSeverity(
						severity.Error,
					),
				}
			}

			storageEncrypted := block.GetAttribute("storage_encrypted")
			if storageEncrypted.IsFalse() {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' has storage encrypted set to false", block.FullName()),
						storageEncrypted.Range(),
						storageEncrypted,
						severity.Error,
					),
				}
			}
			return nil
		},
	})
}
