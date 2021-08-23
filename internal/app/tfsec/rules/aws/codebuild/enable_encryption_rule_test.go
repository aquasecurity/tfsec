package codebuild
// 
// // generator-locked
// import (
// 	"fmt"
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// 
// 	"github.com/aquasecurity/defsec/severity"
// 
// 	"github.com/stretchr/testify/assert"
// )
// 
// func Test_AWSCodeBuildProjectEncryptionNotDisabled(t *testing.T) {
// 	expectedCode := "aws-codebuild-enable-encryption"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "Rule should not pass when artifact encryption is disabled in ID Build Project",
// 			source: `
// resource "aws_codebuild_project" "codebuild" {
// 	// other config
// 
// 	artifacts {
// 		encryption_disabled = true
// 	}
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Rule should not pass when artifact encryption is disabled on any secondary artifacts in ID Build Project",
// 			source: `
// resource "aws_codebuild_project" "codebuild" {
// 	// other config
// 
// 	secondary_artifacts {
// 		encryption_disabled = false
// 	}
// 
// 	secondary_artifacts {
// 		encryption_disabled = true
// 	}
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Rule should pass when artifact encryption enabled in ID Build Project",
// 			source: `
// resource "aws_codebuild_project" "codebuild" {
// 	// other config
// 
// 	artifacts {
// 		encryption_disabled = false
// 	}
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Rule should pass when artifact encryption attribute is not present in ID Build Project",
// 			source: `
// resource "aws_codebuild_project" "codebuild" {
// 	// other config
// 
// 	artifacts {
// 	}
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Rule should pass when artifact encryption enabled in secondary artifacts in ID Build Project",
// 			source: `
// resource "aws_codebuild_project" "codebuild" {
// 	// other config
// 
// 	secondary_artifacts {
// 		encryption_disabled = false
// 	}
// 
// 	secondary_artifacts {
// 		encryption_disabled = false
// 		type = "NO_ARTIFACTS"
// 	}
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Rule should pass when artifact encryption attribute is not present in secondary artifacts in ID Build Project",
// 			source: `
// resource "aws_codebuild_project" "codebuild" {
// 	// other config
// 
// 	secondary_artifacts {
// 	}
// 
// 	secondary_artifacts {
// 	}
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 	}
// 
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 
// 			results := testutil.ScanHCL(test.source, t)
// 			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
// 		})
// 	}
// 
// 	t.Run("Rule should report a warning when artifact encryption is disabled but the type is set to NO_ARTIFACTS in ID Build Project", func(t *testing.T) {
// 
// 		results := testutil.ScanHCL(`
// resource "aws_codebuild_project" "codebuild" {
// 	// other config
// 
// 	artifacts {
// 		encryption_disabled = true
// 		type = "NO_ARTIFACTS"
// 	}
// }
// `, t)
// 		for _, result := range results {
// 			if result.RuleID == "aws-codebuild-enable-encryption" {
// 				assert.True(t, result.Severity == severity.High, fmt.Sprintf("Result with code '%s' had wrong Severity reported '%s'", result.RuleID, result.Severity))
// 			}
// 		}
// 	})
// }
