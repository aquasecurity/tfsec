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

			// function contents here

			return nil
		},
	})
}
