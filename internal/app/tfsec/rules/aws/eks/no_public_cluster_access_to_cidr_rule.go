package eks

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/eks"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/cidr"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS068",
		BadExample: []string{`
 resource "aws_eks_cluster" "bad_example" {
     // other config 
 
     name = "bad_example_cluster"
     role_arn = var.cluster_arn
     vpc_config {
         endpoint_public_access = true
     }
 }
 `},
		GoodExample: []string{`
 resource "aws_eks_cluster" "good_example" {
     // other config 
 
     name = "good_example_cluster"
     role_arn = var.cluster_arn
     vpc_config {
         endpoint_public_access = true
         public_access_cidrs = ["10.2.0.0/8"]
     }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#vpc_config",
			"https://docs.aws.amazon.com/eks/latest/userguide/create-public-private-vpc.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_eks_cluster"},
		Base:           eks.CheckNoPublicClusterAccessToCidr,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("vpc_config") {
				return
			}
			vpcConfig := resourceBlock.GetBlock("vpc_config")

			publicAccessEnabledAttr := vpcConfig.GetAttribute("endpoint_public_access")
			if publicAccessEnabledAttr.IsNotNil() && publicAccessEnabledAttr.IsFalse() {
				return
			}

			publicAccessCidrsAttr := vpcConfig.GetAttribute("public_access_cidrs")
			if publicAccessCidrsAttr.IsNil() {
				results.Add("Resource uses the default public access cidr of 0.0.0.0/0", vpcConfig)
			} else if cidr.IsAttributeOpen(publicAccessCidrsAttr) {
				results.Add("Resource has public access cidr explicitly set to wide open", publicAccessCidrsAttr)
			}

			return results
		},
	})
}
