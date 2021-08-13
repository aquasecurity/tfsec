package eks

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
		LegacyID:  "AWS066",
		Service:   "eks",
		ShortCode: "encrypt-secrets",
		Documentation: rule.RuleDocumentation{
			Summary:    "EKS should have the encryption of secrets enabled",
			Impact:     "EKS secrets could be read if compromised",
			Resolution: "Enable encryption of EKS secrets",
			Explanation: `
EKS cluster resources should have the encryption_config block set with protection of the secrets resource.
`,
			BadExample: []string{`
resource "aws_eks_cluster" "bad_example" {
    name = "bad_example_cluster"

    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`},
			GoodExample: []string{`
resource "aws_eks_cluster" "good_example" {
    encryption_config {
        resources = [ "secrets" ]
        provider {
            key_arn = var.kms_arn
        }
    }

    name = "good_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#encryption_config",
				"https://aws.amazon.com/about-aws/whats-new/2020/03/amazon-eks-adds-envelope-encryption-for-secrets-with-aws-kms/",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_eks_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("encryption_config") {
				set.AddResult().
					WithDescription("Resource '%s' has no encryptionConfigBlock block", resourceBlock.FullName())
				return
			}

			encryptionConfigBlock := resourceBlock.GetBlock("encryption_config")
			if encryptionConfigBlock.MissingChild("resources") {
				set.AddResult().
					WithDescription("Resource '%s' has encryptionConfigBlock block with no resourcesAttr attribute specified", resourceBlock.FullName()).
					WithBlock(encryptionConfigBlock)
				return
			}

			resourcesAttr := encryptionConfigBlock.GetAttribute("resources")
			if !resourcesAttr.Contains("secrets") {
				set.AddResult().
					WithDescription("Resource '%s' does not include secrets in encrypted resources", resourceBlock.FullName()).
					WithAttribute(resourcesAttr)
			}

			if encryptionConfigBlock.MissingChild("provider") {
				set.AddResult().
					WithDescription("Resource '%s' has encryptionConfigBlock block with no provider block specified", resourceBlock.FullName())
				return
			}

			providerBlock := encryptionConfigBlock.GetBlock("provider")
			if providerBlock.MissingChild("key_arn") {
				set.AddResult().
					WithDescription("Resource '%s' has encryptionConfigBlock block with provider block specified missing key arn", resourceBlock.FullName())
				return
			}

			keyArnAttr := providerBlock.GetAttribute("key_arn")
			if keyArnAttr.IsEmpty() {
				set.AddResult().
					WithDescription("Resource '%s' has encryptionConfigBlock block with provider block specified but key_arn is empty", resourceBlock.FullName()).
					WithAttribute(keyArnAttr)
			}

		},
	})
}
