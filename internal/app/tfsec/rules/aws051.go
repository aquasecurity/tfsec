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

const AWSRDSAuroraClusterEncryptionDisabled = "AWS051"
const AWSRDSAuroraClusterEncryptionDisabledDescription = "There is no encryption specified or encryption is disabled on the RDS Cluster."
const AWSRDSAuroraClusterEncryptionDisabledImpact = "Data can be read from the RDS cluster if it is compromised"
const AWSRDSAuroraClusterEncryptionDisabledResolution = "Enable encryption for RDS clusters and instances"
const AWSRDSAuroraClusterEncryptionDisabledExplanation = `
Encryption should be enabled for an RDS Aurora cluster. 

When enabling encryption by setting the kms_key_id, the storage_encrypted must also be set to true. 
`
const AWSRDSAuroraClusterEncryptionDisabledBadExample = `
resource "aws_rds_cluster" "bad_example" {
  name       = "bar"
  kms_key_id = ""
}`
const AWSRDSAuroraClusterEncryptionDisabledGoodExample = `
resource "aws_rds_cluster" "good_example" {
  name              = "bar"
  kms_key_id  = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
  storage_encrypted = true
}`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSRDSAuroraClusterEncryptionDisabled,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSRDSAuroraClusterEncryptionDisabledDescription,
			Impact:      AWSRDSAuroraClusterEncryptionDisabledImpact,
			Resolution:  AWSRDSAuroraClusterEncryptionDisabledResolution,
			Explanation: AWSRDSAuroraClusterEncryptionDisabledExplanation,
			BadExample:  AWSRDSAuroraClusterEncryptionDisabledBadExample,
			GoodExample: AWSRDSAuroraClusterEncryptionDisabledGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_rds_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			kmsKeyIdAttr := resourceBlock.GetAttribute("kms_key_id")
			storageEncryptedattr := resourceBlock.GetAttribute("storage_encrypted")

			if (kmsKeyIdAttr == nil || kmsKeyIdAttr.IsEmpty()) &&
				(storageEncryptedattr == nil || storageEncryptedattr.IsFalse()) {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a disabled RDS Cluster encryption.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			} else if kmsKeyIdAttr != nil && kmsKeyIdAttr.Equals("") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a disabled RDS Cluster encryption.", resourceBlock.FullName())).
						WithRange(kmsKeyIdAttr.Range()).
						WithAttributeAnnotation(kmsKeyIdAttr),
				)
			} else if storageEncryptedattr == nil || storageEncryptedattr.IsFalse() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a enabled RDS Cluster encryption but not the required encrypted_storage.", resourceBlock.FullName())).
						WithRange(kmsKeyIdAttr.Range()).
						WithAttributeAnnotation(kmsKeyIdAttr),
				)
			}
		},
	})
}
