package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const AWSPubliclyAccessibleResource scanner.RuleCode = "AWS011"
const AWSPubliclyAccessibleResourceDescription scanner.RuleSummary = "A resource is marked as publicly accessible."
const AWSPubliclyAccessibleResourceExplanation = `
Database resources should not publicly available. You should limit all access to the minimum that is required for your application to function. 
`
const AWSPubliclyAccessibleResourceBadExample = `
resource "aws_db_instance" "my-resource" {
	publicly_accessible = true
}
`
const AWSPubliclyAccessibleResourceGoodExample = `
resource "aws_db_instance" "my-resource" {
	publicly_accessible = false
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSPubliclyAccessibleResource,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSPubliclyAccessibleResourceDescription,
			Explanation: AWSPubliclyAccessibleResourceExplanation,
			BadExample:  AWSPubliclyAccessibleResourceBadExample,
			GoodExample: AWSPubliclyAccessibleResourceGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_instance", "aws_dms_replication_instance", "aws_rds_cluster_instance", "aws_redshift_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if publicAttr := block.GetAttribute("publicly_accessible"); publicAttr != nil && publicAttr.Type() == cty.Bool {
				if publicAttr.Value().True() {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' is exposed publicly.", block.FullName()),
							publicAttr.Range(),
							publicAttr,
							scanner.SeverityWarning,
						),
					}
				}
			}

			return nil
		},
	})
}
