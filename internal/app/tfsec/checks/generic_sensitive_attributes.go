package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/security"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
	"github.com/zclconf/go-cty/cty"
)

// GenericSensitiveAttributes See https://github.com/liamg/tfsec#included-checks for check info
const GenericSensitiveAttributes scanner.RuleID = "GEN003"

var sensitiveWhitelist = []struct {
	Resource  string
	Attribute string
}{
	{
		Resource:  "aws_efs_file_system",
		Attribute: "creation_token",
	},
	{
		Resource:  "aws_instance",
		Attribute: "get_password_data",
	},
}

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:          GenericSensitiveAttributes,
		RequiredTypes: []string{"resource", "provider", "module"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			attributes := block.GetAttributes()

			var results []scanner.Result
		SKIP:
			for _, attribute := range attributes {
				for _, whitelisted := range sensitiveWhitelist {
					if whitelisted.Resource == block.Labels()[0] && whitelisted.Attribute == attribute.Name() {
						continue SKIP
					}
				}
				if security.IsSensitiveAttribute(attribute.Name()) {
					if attribute.Type() == cty.String && attribute.Value().AsString() != "" {
						results = append(results, check.NewResultWithValueAnnotation(
							fmt.Sprintf("Block '%s' includes a potentially sensitive attribute which is defined within the project.", block.Name()),
							attribute.Range(),
							attribute,
							scanner.SeverityWarning,
						))
					}

				}
			}

			return results
		},
	})
}
