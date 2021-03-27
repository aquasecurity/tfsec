package test

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSCodeBuildProjectEncryptionNotDisabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "Check should not pass when artifact encryption is disabled in Code Build Project",
			source: `
resource "aws_codebuild_project" "codebuild" {
	// other config

	artifacts {
		encryption_disabled = true
	}
}
`,
			mustIncludeResultCode: checks.AWSCodeBuildProjectEncryptionNotDisabled,
		},
		{
			name: "Check should not pass when artifact encryption is disabled on any secondary artifacts in Code Build Project",
			source: `
resource "aws_codebuild_project" "codebuild" {
	// other config

	secondary_artifacts = [
		{
			encryption_disabled = false
		},
		{
			encryption_disabled = true
		}
	]
}
`,
			mustIncludeResultCode: checks.AWSCodeBuildProjectEncryptionNotDisabled,
		},
		{
			name: "Check should pass when artifact encryption enabled in Code Build Project",
			source: `
resource "aws_codebuild_project" "codebuild" {
	// other config

	artifacts {
		encryption_disabled = false
	}
}
`,
			mustExcludeResultCode: checks.AWSCodeBuildProjectEncryptionNotDisabled,
		},
		{
			name: "Check should pass when artifact encryption attribute is not present in Code Build Project",
			source: `
resource "aws_codebuild_project" "codebuild" {
	// other config

	artifacts {
	}
}
`,
			mustExcludeResultCode: checks.AWSCodeBuildProjectEncryptionNotDisabled,
		},
		{
			name: "Check should pass when artifact encryption enabled in secondary artifacts in Code Build Project",
			source: `
resource "aws_codebuild_project" "codebuild" {
	// other config

	secondary_artifacts = [
		{
			encryption_disabled = false
		},
		{
			encryption_disabled = false
		}
	]
}
`,
			mustExcludeResultCode: checks.AWSCodeBuildProjectEncryptionNotDisabled,
		},
		{
			name: "Check should pass when artifact encryption attribute is not present in secondary artifacts in Code Build Project",
			source: `
resource "aws_codebuild_project" "codebuild" {
	// other config

	secondary_artifacts = [
		{
		},
		{
		}
	]
}
`,
			mustExcludeResultCode: checks.AWSCodeBuildProjectEncryptionNotDisabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

	t.Run("Check should report a warning when artifact encryption is disabled but the type is set to NO_ARTIFACTS in Code Build Project", func(t *testing.T) {
		results := scanSource(`
resource "aws_codebuild_project" "codebuild" {
	// other config

	artifacts {
		encryption_disabled = true,
		type = "NO_ARTIFACTS"
	}
}
`)
		for _, result := range results {
			if result.RuleID == checks.AWSCodeBuildProjectEncryptionNotDisabled {
				assert.True(t, result.Severity == scanner.SeverityWarning, fmt.Sprintf("Result with code '%s' had wrong Severity reported '%s'", result.RuleID, result.Severity))
			}
		}
	})
}
