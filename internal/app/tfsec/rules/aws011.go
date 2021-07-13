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

	"github.com/zclconf/go-cty/cty"
)

const AWSPubliclyAccessibleResource = "AWS011"
const AWSPubliclyAccessibleResourceDescription = "A database resource is marked as publicly accessible."
const AWSPubliclyAccessibleResourceImpact = "The database instance is publicly accessible"
const AWSPubliclyAccessibleResourceResolution = "Set the database to not be publicly accessible"
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
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_db_instance", "aws_dms_replication_instance", "aws_rds_cluster_instance", "aws_redshift_cluster"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if publicAttr := resourceBlock.GetAttribute("publicly_accessible"); publicAttr != nil && publicAttr.Type() == cty.Bool {
				if publicAttr.Value().True() {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' is exposed publicly.", resourceBlock.FullName())).
							WithRange(publicAttr.Range()).
							WithAttributeAnnotation(publicAttr),
					)
				}
			}

		},
	})
}
