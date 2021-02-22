package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSEKSClusterNotOpenPublicly scanner.RuleCode = "AWS068"
const AWSEKSClusterNotOpenPubliclyDescription scanner.RuleSummary = "EKS cluster should not have open CIDR range for public access"
const AWSEKSClusterNotOpenPubliclyExplanation = `
EKS Clusters have public access cidrs set to 0.0.0.0/0 by default which is wide open to the internet. This should be explicitly set to a more specific CIDR range
`
const AWSEKSClusterNotOpenPubliclyBadExample = `
resource "aws_eks_cluster" "bad_example" {
    // other config 

    name = "bad_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = true
    }
}
`
const AWSEKSClusterNotOpenPubliclyGoodExample = `
resource "aws_eks_cluster" "good_example" {
    // other config 

    name = "good_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = true
        public_access_cidrs = ["10.2.0.0/8"]
    }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSEKSClusterNotOpenPublicly,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSEKSClusterNotOpenPubliclyDescription,
			Explanation: AWSEKSClusterNotOpenPubliclyExplanation,
			BadExample:  AWSEKSClusterNotOpenPubliclyBadExample,
			GoodExample: AWSEKSClusterNotOpenPubliclyGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#vpc_config",
				"https://docs.aws.amazon.com/eks/latest/userguide/create-public-private-vpc.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_eks_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("vpc_config") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' has no vpc_config block specified so default public access cidrs is set", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			vpcConfig := block.GetBlock("vpc_config")
			if vpcConfig.MissingChild("public_access_cidrs") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' is using default public access cidrs in the vpc config", block.FullName()),
						vpcConfig.Range(),
						scanner.SeverityError,
					),
				}
			}

			publicAccessCidrs := vpcConfig.GetAttribute("public_access_cidrs")
			if isOpenCidr(publicAccessCidrs, scanner.AWSProvider) {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' has public access cidr explicitly set to wide open", block.FullName()),
						publicAccessCidrs.Range(),
						publicAccessCidrs,
						scanner.SeverityError,
					),
				}
			}
			return nil
		},
	})
}
