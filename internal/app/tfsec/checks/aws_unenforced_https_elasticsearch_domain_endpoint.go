package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSUnenforcedHTTPSElasticsearchDomainEndpoint See
// https://github.com/tfsec/tfsec#included-checks for check info
const AWSUnenforcedHTTPSElasticsearchDomainEndpoint scanner.RuleID = "AWS033"
const AWSUnenforcedHTTPSElasticsearchDomainEndpointDescription scanner.RuleDescription = "Elasticsearch doesn't enforce HTTPS traffic."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSUnenforcedHTTPSElasticsearchDomainEndpoint,
		Description:    AWSUnenforcedHTTPSElasticsearchDomainEndpointDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticsearch_domain"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			endpointBlock := block.GetBlock("domain_endpoint_options")
			if endpointBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with plaintext traffic (missing domain_endpoint_options block).", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			enforceHTTPSAttr := endpointBlock.GetAttribute("enforce_https")
			if enforceHTTPSAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with plaintext traffic (missing enforce_https attribute).", block.Name()),
						endpointBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			isTrueBool := enforceHTTPSAttr.Type() == cty.Bool && enforceHTTPSAttr.Value().True()
			isTrueString := enforceHTTPSAttr.Type() == cty.String &&
				enforceHTTPSAttr.Value().Equals(cty.StringVal("true")).True()
			enforcedHTTPS := isTrueBool || isTrueString
			if !enforcedHTTPS {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with plaintext traffic (enabled attribute set to false).", block.Name()),
						endpointBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
