package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSRDSEncryptionNotEnabled scanner.RuleCode = "AWS052"
const AWSRDSEncryptionNotEnabledDescription scanner.RuleSummary = "RDS encryption has not been enabled at a DB Instance level."
const AWSRDSEncryptionNotEnabledExplanation = `
Encryption should be enabled for an RDS Database instances. 

When enabling encryption by setting the kms_key_id. 
`
const AWSRDSEncryptionNotEnabledBadExample = `
resource "aws_db_instance" "my-db-instance" {
	
}
`
const AWSRDSEncryptionNotEnabledGoodExample = `
resource "aws_db_instance" "my-db-instance" {
	kms_key_id  = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSRDSEncryptionNotEnabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSRDSEncryptionNotEnabledDescription,
			Explanation: AWSRDSEncryptionNotEnabledExplanation,
			BadExample:  AWSRDSEncryptionNotEnabledBadExample,
			GoodExample: AWSRDSEncryptionNotEnabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance",
				"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_instance"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			kmsKeyIdAttr := block.GetAttribute("kms_key_id")

			if kmsKeyIdAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a disabled RDS Instance Encryption.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else if kmsKeyIdAttr.Equals("") {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines a disabled RDS Instance Encryption.", block.FullName()),
						kmsKeyIdAttr.Range(),
						kmsKeyIdAttr,
						scanner.SeverityError,
					),
				}
			}
			return nil
		},
	})
}
