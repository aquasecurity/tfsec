package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// AWSCloudFrontDoesNotHaveAWaf See https://github.com/tfsec/tfsec#included-checks for check info
const AWSCloudFrontDoesNotHaveAWaf scanner.RuleID = "AWS045"
const AWSCloudFrontDoesNotHaveAWafDescription scanner.RuleDescription = "CloudFront distribution does not have a WAF in front."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSCloudFrontDoesNotHaveAWaf,
		Description:    AWSCloudFrontDoesNotHaveAWafDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudfront_distribution"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			wafAclIdBlock := block.GetAttribute("web_acl_id")
			if wafAclIdBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not have a WAF in front of it.", block.Name()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			}
			return nil
		},
	})
}
