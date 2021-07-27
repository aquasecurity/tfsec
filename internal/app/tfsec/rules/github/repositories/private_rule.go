package repositories

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "GIT001",
		ShortCode: "private",
		Documentation: rule.RuleDocumentation{
			Summary:    "Github repository shouldn't be public.",
			Impact:     "Anyone can read the contents of the GitHub repository and leak IP",
			Resolution: "Make sensitive or commercially important repositories private",
			Explanation: `
Github repository should be set to be private.

You can do this by either setting <code>private</code> attribute to 'true' or <code>visibility</code> attribute to 'internal' or 'private'.
`,
			BadExample: []string{`
resource "github_repository" "bad_example" {
  name        = "example"
  description = "My awesome codebase"

  visibility  = "public"

  template {
    owner = "github"
    repository = "terraform-module-template"
  }
}
`},
			GoodExample: []string{`
resource "github_repository" "good_example" {
  name        = "example"
  description = "My awesome codebase"

  visibility  = "private"

  template {
    owner = "github"
    repository = "terraform-module-template"
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/integrations/github/latest/docs/resources/repository",
				"https://docs.github.com/en/github/creating-cloning-and-archiving-repositories/about-repository-visibility",
				"https://docs.github.com/en/github/creating-cloning-and-archiving-repositories/about-repository-visibility#about-internal-repositories",
			},
		},
		Service:         "repositories",
		Provider:        provider.GitHubProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"github_repository"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			privateAttribute := resourceBlock.GetAttribute("private")
			visibilityAttribute := resourceBlock.GetAttribute("visibility")
			if visibilityAttribute == nil && privateAttribute == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' is missing both of `private` or `visibility` attributes - one of these is required to make repository private", resourceBlock.FullName())),
				)
				return
			}

			// this should be evaluated first as visibility overrides private
			if visibilityAttribute != nil {
				if visibilityAttribute.Equals("public") {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' has visibility set to public - visibility should be set to `private` or `internal` to make repository private", resourceBlock.FullName())).
							WithAttribute(visibilityAttribute),
					)
				}
				// stop here as visibility parameter trumps the private one
				// see https://registry.terraform.io/providers/integrations/github/latest/docs/resources/repository
				return
			}

			// this should be evaluated first as visibility overrides private
			if privateAttribute != nil {
				if privateAttribute.IsFalse() {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' has private set to false - it should be set to `true` to make repository private", resourceBlock.FullName())),
					)
				}
			}

		},
	})
}
