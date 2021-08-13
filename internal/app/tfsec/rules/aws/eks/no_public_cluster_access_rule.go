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
		LegacyID:  "AWS069",
		Service:   "eks",
		ShortCode: "no-public-cluster-access",
		Documentation: rule.RuleDocumentation{
			Summary:    "EKS Clusters should have the public access disabled",
			Impact:     "EKS can be access from the internet",
			Resolution: "Don't enable public access to EKS Clusters",
			Explanation: `
EKS clusters are available publicly by default, this should be explicitly disabled in the vpc_config of the EKS cluster resource.
`,
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
				"https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_eks_cluster"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("vpc_config") {
				set.AddResult().
					WithDescription("Resource '%s' has no vpc_config block specified so default public access is enabled", resourceBlock.FullName())
				return
			}

			vpcConfig := resourceBlock.GetBlock("vpc_config")
			if vpcConfig.MissingChild("endpoint_public_access") {
				set.AddResult().
					WithDescription("Resource '%s' is using default public access in the vpc config", resourceBlock.FullName()).
					WithBlock(vpcConfig)
				return
			}

			publicAccessEnabledAttr := vpcConfig.GetAttribute("endpoint_public_access")
			if publicAccessEnabledAttr.IsTrue() {
				set.AddResult().
					WithDescription("Resource '%s' has public access is explicitly set to enabled", resourceBlock.FullName()).
					WithAttribute(publicAccessEnabledAttr)
			}
		},
	})
}
