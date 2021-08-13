package rds

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS052",
		Service:   "rds",
		ShortCode: "encrypt-instance-storage-data",
		Documentation: rule.RuleDocumentation{
			Summary:    "RDS encryption has not been enabled at a DB Instance level.",
			Impact:     "Data can be read from RDS instances if compromised",
			Resolution: "Enable encryption for RDS instances",
			Explanation: `
Encryption should be enabled for an RDS Database instances. 

When enabling encryption by setting the kms_key_id. 
`,
			BadExample: []string{`
resource "aws_db_instance" "bad_example" {
	
}
`},
			GoodExample: []string{`
resource "aws_db_instance" "good_example" {
	storage_encrypted  = true
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance",
				"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_db_instance"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("storage_encrypted") {
				set.AddResult().
					WithDescription("Resource '%s' has no storage encryption defined.", resourceBlock.FullName())
				return
			}

			storageEncryptedAttr := resourceBlock.GetAttribute("storage_encrypted")
			if storageEncryptedAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' has storage encrypted set to false", resourceBlock.FullName()).
					WithAttribute(storageEncryptedAttr)
			}
		},
	})
}
