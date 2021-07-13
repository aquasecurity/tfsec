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

const AWSRedshiftNotDeployedInEC2Classic = "AWS087"
const AWSRedshiftNotDeployedInEC2ClassicDescription = "Redshift cluster should be deployed into a specific VPC"
const AWSRedshiftNotDeployedInEC2ClassicImpact = "Redshift cluster does not benefit from VPC security if it is deployed in EC2 classic mode"
const AWSRedshiftNotDeployedInEC2ClassicResolution = "Deploy Redshift cluster into a non default VPC"
const AWSRedshiftNotDeployedInEC2ClassicExplanation = `
Redshift clusters that are created without subnet details will be created in EC2 classic mode, meaning that they will be outside of a known VPC and running in tennant.

In order to benefit from the additional security features achieved with using an owned VPC, the subnet should be set.
`
const AWSRedshiftNotDeployedInEC2ClassicBadExample = `
resource "aws_redshift_cluster" "bad_example" {
	cluster_identifier = "tf-redshift-cluster"
	database_name      = "mydb"
	master_username    = "foo"
	master_password    = "Mustbe8characters"
	node_type          = "dc1.large"
	cluster_type       = "single-node"
}
`
const AWSRedshiftNotDeployedInEC2ClassicGoodExample = `
resource "aws_redshift_cluster" "good_example" {
	cluster_identifier = "tf-redshift-cluster"
	database_name      = "mydb"
	master_username    = "foo"
	master_password    = "Mustbe8characters"
	node_type          = "dc1.large"
	cluster_type       = "single-node"

	cluster_subnet_group_name = "redshift_subnet"
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSRedshiftNotDeployedInEC2Classic,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSRedshiftNotDeployedInEC2ClassicDescription,
			Explanation: AWSRedshiftNotDeployedInEC2ClassicExplanation,
			Impact:      AWSRedshiftNotDeployedInEC2ClassicImpact,
			Resolution:  AWSRedshiftNotDeployedInEC2ClassicResolution,
			BadExample:  AWSRedshiftNotDeployedInEC2ClassicBadExample,
			GoodExample: AWSRedshiftNotDeployedInEC2ClassicGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#cluster_subnet_group_name",
				"https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_redshift_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			if resourceBlock.MissingChild("cluster_subnet_group_name") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' is being deployed outside of a VPC", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			}
		},
	})
}
