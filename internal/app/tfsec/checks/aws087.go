package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSRedshiftNotDeployedInEC2Classic scanner.RuleCode = "AWS087"
const AWSRedshiftNotDeployedInEC2ClassicDescription scanner.RuleSummary = "Redshift cluster should be deployed into a specific VPC"
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
	scanner.RegisterCheck(scanner.Check{
		Code: AWSRedshiftNotDeployedInEC2Classic,
		Documentation: scanner.CheckDocumentation{
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
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_redshift_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if block.MissingChild("cluster_subnet_group_name") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' is being deployed outside of a VPC", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}
			return nil
		},
	})
}
