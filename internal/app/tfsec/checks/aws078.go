package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSCodeBuildProjectEncryptionNotDisabled scanner.RuleCode = "AWS078"
const AWSCodeBuildProjectEncryptionNotDisabledDescription scanner.RuleSummary = "CodeBuild Project artifacts encryption should not be disabled"
const AWSCodeBuildProjectEncryptionNotDisabledExplanation = `
All artifacts produced by your CodeBuild project pipeline should always be encrypted
`
const AWSCodeBuildProjectEncryptionNotDisabledBadExample = `
resource "aws_codebuild_project" "bad_example" {
	// other config

	artifacts {
		// other artifacts config

		encryption_disabled = true
	}
}

resource "aws_codebuild_project" "bad_example" {
	// other config including primary artifacts

	secondary_artifacts {
		// other artifacts config
		
		encryption_disabled = false
	}

	secondary_artifacts {
		// other artifacts config

		encryption_disabled = true
	}
}
`
const AWSCodeBuildProjectEncryptionNotDisabledGoodExample = `
resource "aws_codebuild_project" "good_example" {
	// other config

	artifacts {
		// other artifacts config

		encryption_disabled = false
	}
}

resource "aws_codebuild_project" "good_example" {
	// other config

	artifacts {
		// other artifacts config
	}
}

resource "aws_codebuild_project" "codebuild" {
	// other config

	secondary_artifacts {
		// other artifacts config

		encryption_disabled = false
	}

	secondary_artifacts {
		// other artifacts config
	}
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

			artifactBlockChecker := func(artifactBlock *parser.Block) []scanner.Result {
				if encryptionDisabledAttr := artifactBlock.GetAttribute("encryption_disabled"); encryptionDisabledAttr != nil && encryptionDisabledAttr.IsTrue() {
					artifactType := artifactBlock.GetAttribute("type")

					if artifactType.Equals("NO_ARTIFACTS", parser.IgnoreCase) {
						return []scanner.Result{
							check.NewResult(
								fmt.Sprintf("CodeBuild project '%s' is configured to disable artifact encryption while no artifacts are produced", block.FullName()),
								artifactBlock.Range(),
								scanner.SeverityWarning,
							),
						}
					} else {
						return []scanner.Result{
							check.NewResult(
								fmt.Sprintf("CodeBuild project '%s' does not encrypt produced artifacts", block.FullName()),
								artifactBlock.Range(),
								scanner.SeverityError,
							),
						}
					}
				}

				return []scanner.Result{}
			}

			artifact := block.GetBlock("artifacts")
			results := artifactBlockChecker(artifact)

			if secondaryArtifacts := block.GetBlocks("secondary_artifacts"); secondaryArtifacts != nil && len(secondaryArtifacts) > 0 {
				for _, secondaryArtifact := range secondaryArtifacts {
					results = append(results, artifactBlockChecker(secondaryArtifact)...)
				}
			}

			if len(results) == 0 {
				return nil
			}
			return results
		},
	})
}
