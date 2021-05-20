package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSEKSClusterPublicAccessDisabled scanner.RuleCode = "AWS069"
const AWSEKSClusterPublicAccessDisabledDescription scanner.RuleSummary = "EKS Clusters should have the public access disabled"
const AWSEKSClusterPublicAccessDisabledImpact = "EKS can be access from the internet"
const AWSEKSClusterPublicAccessDisabledResolution = "Don't enable public access to EKS Clusters"
const AWSEKSClusterPublicAccessDisabledExplanation = `
EKS clusters are available publicly by default, this should be explicitly disabled in the vpc_config of the EKS cluster resource.
`
const AWSEKSClusterPublicAccessDisabledBadExample = `
resource "aws_eks_cluster" "bad_example" {
    // other config 

    name = "bad_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
		endpoint_public_access = true
		public_access_cidrs = ["0.0.0.0/0"]
    }
}
`
const AWSEKSClusterPublicAccessDisabledGoodExample = `
resource "aws_eks_cluster" "good_example" {
    // other config 

    name = "good_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSEKSClusterPublicAccessDisabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSEKSClusterPublicAccessDisabledDescription,
			Impact:      AWSEKSClusterPublicAccessDisabledImpact,
			Resolution:  AWSEKSClusterPublicAccessDisabledResolution,
			Explanation: AWSEKSClusterPublicAccessDisabledExplanation,
			BadExample:  AWSEKSClusterPublicAccessDisabledBadExample,
			GoodExample: AWSEKSClusterPublicAccessDisabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#endpoint_public_access",
				"https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_eks_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("vpc_config") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' has no vpc_config block specified so default public access is enabled", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			vpcConfig := block.GetBlock("vpc_config")
			if vpcConfig.MissingChild("endpoint_public_access") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' is using default public access in the vpc config", block.FullName()),
						vpcConfig.Range(),
						scanner.SeverityError,
					),
				}
			}

			publicAccessEnabled := vpcConfig.GetAttribute("endpoint_public_access")
			if publicAccessEnabled.IsTrue() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' has public access is explicitly set to enabled", block.FullName()),
						publicAccessEnabled.Range(),
						publicAccessEnabled,
						scanner.SeverityError,
					),
				}
			}
			return nil
		},
	})
}
