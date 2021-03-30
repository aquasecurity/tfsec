package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSDAXEncryptedAtRest scanner.RuleCode = "AWS078"
const AWSDAXEncryptedAtRestDescription scanner.RuleSummary = "DAX Cluster should always encrypt data at rest"
const AWSDAXEncryptedAtRestExplanation = `
Amazon DynamoDB Accelerator (DAX) encryption at rest provides an additional layer of data protection by helping secure your data from unauthorized access to the underlying storage.
`
const AWSDAXEncryptedAtRestBadExample = `
resource "aws_dax_cluster" "bad_example" {
	// no server side encryption at all
}

resource "aws_dax_cluster" "bad_example" {
	// other DAX config

	server_side_encryption {
		// empty server side encryption config
	}
}

resource "aws_dax_cluster" "bad_example" {
	// other DAX config

	server_side_encryption {
		enabled = false // disabled server side encryption
	}
}
`
const AWSDAXEncryptedAtRestGoodExample = `
resource "aws_dax_cluster" "good_example" {
	// other DAX config

	server_side_encryption {
		enabled = true // enabled server side encryption
	}
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
			Links: []string{
				"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionAtRest.html",
				"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dax-cluster.html",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dax_cluster#server_side_encryption",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_dax_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			result := check.NewResult(
				"",
				block.Range(),
				scanner.SeverityError,
			)

			if block.MissingChild("server_side_encryption") {
				result.Description = fmt.Sprintf("DAX cluster '%s' does not have server side encryption configured. By default it is disabled.", block.FullName())
				return []scanner.Result{result}
			}

			sseBlock := block.GetBlock("server_side_encryption")
			if sseBlock.MissingChild("enabled") {
				result.Description = fmt.Sprintf("DAX cluster '%s' server side encryption block is empty. By default SSE is disabled.", block.FullName())
				result.Range = sseBlock.Range()
				return []scanner.Result{result}
			}

			if sseEnabledAttr := sseBlock.GetAttribute("enabled"); sseEnabledAttr.IsFalse() {
				result.Description = fmt.Sprintf("DAX cluster '%s' has disabled server side encryption", block.FullName())
				result.Range = sseEnabledAttr.Range()
				return []scanner.Result{result}
			}

			return nil
		},
	})
}
