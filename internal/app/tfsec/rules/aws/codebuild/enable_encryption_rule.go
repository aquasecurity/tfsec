package codebuild

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/codebuild"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS080",
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
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_codebuild_project"},
		Base:           codebuild.CheckEnableEncryption,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			blocks := resourceBlock.GetBlocks("secondary_artifacts")
			if artifact := resourceBlock.GetBlock("artifacts"); artifact.IsNotNil() {
				blocks = append(blocks, artifact)
			}

			for _, artifactBlock := range blocks {
				encryptionDisabledAttr := artifactBlock.GetAttribute("encryption_disabled")
				if encryptionDisabledAttr.IsTrue() {
					artifactTypeAttr := artifactBlock.GetAttribute("type")
					if artifactTypeAttr.Equals("NO_ARTIFACTS", block.IgnoreCase) {
						results.Add("CodeBuild project '%s' is configured to disable artifact encryption while no artifacts are produced", encryptionDisabledAttr)
					} else {
						results.Add("CodeBuild project '%s' does not encrypt produced artifacts", encryptionDisabledAttr)
					}
				}
			}

			return results
		},
	})
}
