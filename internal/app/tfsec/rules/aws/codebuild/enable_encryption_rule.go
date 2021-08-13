package codebuild

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS080",
		Service:   "codebuild",
		ShortCode: "enable-encryption",
		Documentation: rule.RuleDocumentation{
			Summary:    "CodeBuild Project artifacts encryption should not be disabled",
			Impact:     "CodeBuild project artifacts are unencrypted",
			Resolution: "Enable encryption for CodeBuild project artifacts",
			Explanation: `
All artifacts produced by your CodeBuild project pipeline should always be encrypted
`,
			BadExample: []string{`
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
`},
			GoodExample: []string{`
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
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codebuild_project#encryption_disabled",
				"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-artifacts.html",
				"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_codebuild_project"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			blocks := resourceBlock.GetBlocks("secondary_artifacts")

			if artifact := resourceBlock.GetBlock("artifacts"); artifact.IsNotNil() {
				blocks = append(blocks, artifact)
			}

			for _, artifactBlock := range blocks {
				encryptionDisabledAttr := artifactBlock.GetAttribute("encryption_disabled")
				if encryptionDisabledAttr.IsTrue() {
					artifactTypeAttr := artifactBlock.GetAttribute("type")

					if artifactTypeAttr.Equals("NO_ARTIFACTS", block.IgnoreCase) {
						set.AddResult().
							WithDescription("CodeBuild project '%s' is configured to disable artifact encryption while no artifacts are produced", resourceBlock.FullName()).
							WithAttribute(artifactTypeAttr)
					} else {
						set.AddResult().
							WithDescription("CodeBuild project '%s' does not encrypt produced artifacts", resourceBlock.FullName()).
							WithAttribute(encryptionDisabledAttr)
					}
				}
			}
		},
	})
}
