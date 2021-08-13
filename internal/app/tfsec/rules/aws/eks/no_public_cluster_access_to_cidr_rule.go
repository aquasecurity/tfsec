package eks

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/cidr"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS068",
		Service:   "eks",
		ShortCode: "no-public-cluster-access-to-cidr",
		Documentation: rule.RuleDocumentation{
			Summary:    "EKS cluster should not have open CIDR range for public access",
			Impact:     "EKS can be access from the internet",
			Resolution: "Don't enable public access to EKS Clusters",
			Explanation: `
EKS Clusters have public access cidrs set to 0.0.0.0/0 by default which is wide open to the internet. This should be explicitly set to a more specific CIDR range
`,
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
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_eks_cluster"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

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
				set.AddResult().
					WithDescription("Resource '%s' uses the default public access cidr of 0.0.0.0/0", resourceBlock.FullName()).
					WithBlock(vpcConfig)

			} else if cidr.IsAttributeOpen(publicAccessCidrsAttr) {
				set.AddResult().
					WithDescription("Resource '%s' has public access cidr explicitly set to wide open", resourceBlock.FullName()).
					WithAttribute(publicAccessCidrsAttr)
			}
		},
	})
}
