package checks

import (
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSCodeBuildProjectEncryptionNotDisabled scanner.RuleCode = "AWS073"
const AWSCodeBuildProjectEncryptionNotDisabledDescription scanner.RuleSummary = "CodeBuild Project artifacts encryption should not be disabled"
const AWSCodeBuildProjectEncryptionNotDisabledExplanation = `

`
const AWSCodeBuildProjectEncryptionNotDisabledBadExample = `
resource "" "bad_example" {

}
`
const AWSCodeBuildProjectEncryptionNotDisabledGoodExample = `
resource "" "good_example" {

}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSCodeBuildProjectEncryptionNotDisabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSCodeBuildProjectEncryptionNotDisabledDescription,
			Explanation: AWSCodeBuildProjectEncryptionNotDisabledExplanation,
			BadExample:  AWSCodeBuildProjectEncryptionNotDisabledBadExample,
			GoodExample: AWSCodeBuildProjectEncryptionNotDisabledGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html",
				"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-artifacts.html",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codebuild_project#encryption_disabled",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_codebuild_project"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			return nil
		},
	})
}
