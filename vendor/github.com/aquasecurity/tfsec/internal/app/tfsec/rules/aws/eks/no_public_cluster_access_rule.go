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
		LegacyID: "AWS069",
		BadExample: []string{`
 resource "aws_eks_cluster" "bad_example" {
     // other config 
 
     name = "bad_example_cluster"
     role_arn = var.cluster_arn
     vpc_config {
 		endpoint_public_access = true
 		public_access_cidrs = ["0.0.0.0/0"]
     }
 }
 `},
		GoodExample: []string{`
 resource "aws_eks_cluster" "good_example" {
     // other config 
 
     name = "good_example_cluster"
     role_arn = var.cluster_arn
     vpc_config {
         endpoint_public_access = false
     }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#endpoint_public_access",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_eks_cluster"},
		Base:           eks.CheckNoPublicClusterAccess,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("vpc_config") {
				results.Add("Resource has no vpc_config block specified so default public access is enabled", resourceBlock)
				return
			}

			vpcConfig := resourceBlock.GetBlock("vpc_config")
			if vpcConfig.MissingChild("endpoint_public_access") {
				results.Add("Resource is using default public access in the vpc config", vpcConfig)
				return
			}

			publicAccessEnabledAttr := vpcConfig.GetAttribute("endpoint_public_access")
			if publicAccessEnabledAttr.IsTrue() {
				results.Add("Resource has public access is explicitly set to enabled", publicAccessEnabledAttr)
			}

			return results
		},
	})
}
