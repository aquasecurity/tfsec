package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSUnencryptedElasticsearchDomain See https://github.com/tfsec/tfsec#included-checks for check info
const AWSUnencryptedElasticsearchDomain scanner.RuleID = "AWS031"
const AWSUnencryptedElasticsearchDomainDescription scanner.RuleDescription = "Elasticsearch domain isn't encrypted at rest."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSUnencryptedElasticsearchDomain,
		Description:    AWSUnencryptedElasticsearchDomainDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticsearch_domain"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			encryptionBlock := block.GetBlock("encrypt_at_rest")
			if encryptionBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted Elasticsearch domain (missing encrypt_at_rest block).", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			enabledAttr := encryptionBlock.GetAttribute("enabled")
			if enabledAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted Elasticsearch domain (missing enabled attribute).", block.Name()),
						encryptionBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			isTrueBool := enabledAttr.Type() == cty.Bool && enabledAttr.Value().True()
			isTrueString := enabledAttr.Type() == cty.String &&
				enabledAttr.Value().Equals(cty.StringVal("true")).True()
			encryptionEnabled := isTrueBool || isTrueString
			if !encryptionEnabled {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted Elasticsearch domain (enabled attribute set to false).", block.Name()),
						encryptionBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
