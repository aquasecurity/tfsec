package eks

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/eks"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS066",
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
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_eks_cluster"},
		Base:           eks.CheckEncryptSecrets,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("encryption_config") {
				results.Add("Resource has no encryptionConfigBlock block", resourceBlock)
				return
			}

			encryptionConfigBlock := resourceBlock.GetBlock("encryption_config")
			if encryptionConfigBlock.MissingChild("resources") {
				results.Add("Resource has encryptionConfigBlock block with no resourcesAttr attribute specified", encryptionConfigBlock)
				return
			}

			resourcesAttr := encryptionConfigBlock.GetAttribute("resources")
			if !resourcesAttr.Contains("secrets") {
				results.Add("Resource does not include secrets in encrypted resources", resourcesAttr)
				return
			}

			if encryptionConfigBlock.MissingChild("provider") {
				results.Add("Resource has encryptionConfigBlock block with no provider block specified", encryptionConfigBlock)
				return
			}

			providerBlock := encryptionConfigBlock.GetBlock("provider")
			if providerBlock.MissingChild("key_arn") {
				results.Add("Resource has encryptionConfigBlock block with provider block specified missing key arn", providerBlock)
				return
			}

			keyArnAttr := providerBlock.GetAttribute("key_arn")
			if keyArnAttr.IsEmpty() {
				results.Add("Resource has encryptionConfigBlock block with provider block specified but key_arn is empty", keyArnAttr)
			}

			return results
		},
	})
}
