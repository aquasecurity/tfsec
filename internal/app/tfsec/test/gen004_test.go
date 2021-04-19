package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_GENEnsureGithubRepositoryIsPrivate(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "should fire if there is no visibility or private attribute",
			source: `
resource "github_repository" "good_example" {
  name        = "example"
  description = "My awesome codebase"

  template {
    owner = "github"
    repository = "terraform-module-template"
  }
}
`,
			mustIncludeResultCode: checks.GENEnsureGithubRepositoryIsPrivate,
		},
		{
			name: "should not fire if private is set to true",
			source: `
resource "github_repository" "good_example" {
  name        = "example"
  description = "My awesome codebase"

  private = true

  template {
    owner = "github"
    repository = "terraform-module-template"
  }
}
`,
			mustExcludeResultCode: checks.GENEnsureGithubRepositoryIsPrivate,
		},
		{
			name: "should not fire if visibility is set to private",
			source: `
resource "github_repository" "good_example" {
  name        = "example"
  description = "My awesome codebase"

  visibility = "private"

  template {
    owner = "github"
    repository = "terraform-module-template"
  }
}
`,
			mustExcludeResultCode: checks.GENEnsureGithubRepositoryIsPrivate,
		},
		{
			name: "should not fire if visibility is set to internal",
			source: `
resource "github_repository" "good_example" {
  name        = "example"
  description = "My awesome codebase"

  visibility = "internal"

  template {
    owner = "github"
    repository = "terraform-module-template"
  }
}
`,
			mustExcludeResultCode: checks.GENEnsureGithubRepositoryIsPrivate,
		},
		{
			name: "should not fire as visibility is overriding private",
			source: `
resource "github_repository" "good_example" {
  name        = "example"
  description = "My awesome codebase"

  private    = false
  visibility = "private"

  template {
    owner = "github"
    repository = "terraform-module-template"
  }
}
`,
			mustExcludeResultCode: checks.GENEnsureGithubRepositoryIsPrivate,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
