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

const AWSEKSClusterNotOpenPublicly = "AWS068"
const AWSEKSClusterNotOpenPubliclyDescription = "EKS cluster should not have open CIDR range for public access"
const AWSEKSClusterNotOpenPubliclyImpact = "EKS can be access from the internet"
const AWSEKSClusterNotOpenPubliclyResolution = "Don't enable public access to EKS Clusters"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSEKSClusterNotOpenPublicly,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSEKSClusterNotOpenPubliclyDescription,
			Impact:      AWSEKSClusterNotOpenPubliclyImpact,
			Resolution:  AWSEKSClusterNotOpenPubliclyResolution,
			Explanation: AWSEKSClusterNotOpenPubliclyExplanation,
			BadExample:  AWSEKSClusterNotOpenPubliclyBadExample,
			GoodExample: AWSEKSClusterNotOpenPubliclyGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#vpc_config",
				"https://docs.aws.amazon.com/eks/latest/userguide/create-public-private-vpc.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_eks_cluster"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("vpc_config") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' has no vpc_config block specified so default public access cidrs is set", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			vpcConfig := resourceBlock.GetBlock("vpc_config")
			if vpcConfig.MissingChild("public_access_cidrs") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' is using default public access cidrs in the vpc config", resourceBlock.FullName())).
						WithRange(vpcConfig.Range()),
				)
				return
			}

			publicAccessCidrsAttr := vpcConfig.GetAttribute("public_access_cidrs")
			if isOpenCidr(publicAccessCidrsAttr) {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' has public access cidr explicitly set to wide open", resourceBlock.FullName())).
						WithRange(publicAccessCidrsAttr.Range()).
						WithAttributeAnnotation(publicAccessCidrsAttr),
				)
			}
		},
	})
}
