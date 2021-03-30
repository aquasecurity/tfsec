package checks

import (
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSDAXEncryptedAtRest scanner.RuleCode = "AWS078"
const AWSDAXEncryptedAtRestDescription scanner.RuleSummary = "DAX Cluster should always encrypt data at rest"
const AWSDAXEncryptedAtRestExplanation = `

`
const AWSDAXEncryptedAtRestBadExample = `
resource "" "bad_example" {

}
`
const AWSDAXEncryptedAtRestGoodExample = `
resource "" "good_example" {

}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSDAXEncryptedAtRest,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSDAXEncryptedAtRestDescription,
			Explanation: AWSDAXEncryptedAtRestExplanation,
			BadExample:  AWSDAXEncryptedAtRestBadExample,
			GoodExample: AWSDAXEncryptedAtRestGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_dax_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			// function contents here

			return nil
		},
	})
}
