package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSPlaintextNodeToNodeElasticsearchTraffic See https://github.com/tfsec/tfsec#included-checks for check info
const AWSPlaintextNodeToNodeElasticsearchTraffic scanner.RuleID = "AWS032"
const AWSPlaintextNodeToNodeElasticsearchTrafficDescription scanner.RuleDescription = "Elasticsearch domain uses plaintext traffic for node to node communication."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSPlaintextNodeToNodeElasticsearchTraffic,
		Description:    AWSPlaintextNodeToNodeElasticsearchTrafficDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticsearch_domain"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			encryptionBlock := block.GetBlock("node_to_node_encryption")
			if encryptionBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with plaintext traffic (missing node_to_node_encryption block).", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			enabledAttr := encryptionBlock.GetAttribute("enabled")
			if enabledAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with plaintext traffic (missing enabled attribute).", block.Name()),
						encryptionBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			isTrueBool := enabledAttr.Type() == cty.Bool && enabledAttr.Value().True()
			isTrueString := enabledAttr.Type() == cty.String &&
				enabledAttr.Value().Equals(cty.StringVal("true")).True()
			nodeToNodeEncryptionEnabled := isTrueBool || isTrueString
			if !nodeToNodeEncryptionEnabled {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with plaintext traffic (enabled attribute set to false).", block.Name()),
						encryptionBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
