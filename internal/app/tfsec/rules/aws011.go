package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

const AWSPubliclyAccessibleResource = "AWS011"
const AWSPubliclyAccessibleResourceDescription = "A database resource is marked as publicly accessible."
const AWSPubliclyAccessibleResourceImpact = "The database instance is publicly accessible"
const AWSPubliclyAccessibleResourceResolution = "Set the database to not be publically accessible"
const AWSPubliclyAccessibleResourceExplanation = `
Database resources should not publicly available. You should limit all access to the minimum that is required for your application to function. 
`
const AWSPubliclyAccessibleResourceBadExample = `
resource "aws_db_instance" "bad_example" {
	publicly_accessible = true
}
`
const AWSPubliclyAccessibleResourceGoodExample = `
resource "aws_db_instance" "good_example" {
	publicly_accessible = false
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSPubliclyAccessibleResource,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSPubliclyAccessibleResourceDescription,
			Impact:      AWSPubliclyAccessibleResourceImpact,
			Resolution:  AWSPubliclyAccessibleResourceResolution,
			Explanation: AWSPubliclyAccessibleResourceExplanation,
			BadExample:  AWSPubliclyAccessibleResourceBadExample,
			GoodExample: AWSPubliclyAccessibleResourceGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance",
			},
		},
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_instance", "aws_dms_replication_instance", "aws_rds_cluster_instance", "aws_redshift_cluster"},
		CheckFunc: func(set result.Set, block *block.Block, _ *hclcontext.Context) {

			if publicAttr := block.GetAttribute("publicly_accessible"); publicAttr != nil && publicAttr.Type() == cty.Bool {
				if publicAttr.Value().True() {
					set.Add(
						result.New().
							WithDescription(fmt.Sprintf("Resource '%s' is exposed publicly.", block.FullName())).
							WithRange(publicAttr.Range()).
							WithAttributeAnnotation(publicAttr).
							WithSeverity(severity.Warning),
					)
				}
			}

		},
	})
}
