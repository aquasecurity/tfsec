package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const GENEnsureGithubRepositoryIsPrivate scanner.RuleCode = "GEN004"
const GENEnsureGithubRepositoryIsPrivateDescription scanner.RuleSummary = "Github repository shouldn't be public."
const GENEnsureGithubRepositoryIsPrivateImpact = "Anyone can read the contents of the GitHub repository and leak IP"
const GENEnsureGithubRepositoryIsPrivateResolution = "Make sensitive or commercially importnt repositories private"
const GENEnsureGithubRepositoryIsPrivateExplanation = `
Github repository should be set to be private.

You can do this by either setting <code>private</code> attribute to 'true' or <code>visibility</code> attribute to 'internal' or 'private'.
`
const GENEnsureGithubRepositoryIsPrivateBadExample = `
resource "github_repository" "bad_example" {
  name        = "example"
  description = "My awesome codebase"

  visibility  = "public"

  template {
    owner = "github"
    repository = "terraform-module-template"
  }
}
`
const GENEnsureGithubRepositoryIsPrivateGoodExample = `
resource "github_repository" "good_example" {
  name        = "example"
  description = "My awesome codebase"

  visibility  = "private"

  template {
    owner = "github"
    repository = "terraform-module-template"
  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: GENEnsureGithubRepositoryIsPrivate,
		Documentation: scanner.CheckDocumentation{
			Summary:     GENEnsureGithubRepositoryIsPrivateDescription,
			Impact:      GENEnsureGithubRepositoryIsPrivateImpact,
			Resolution:  GENEnsureGithubRepositoryIsPrivateResolution,
			Explanation: GENEnsureGithubRepositoryIsPrivateExplanation,
			BadExample:  GENEnsureGithubRepositoryIsPrivateBadExample,
			GoodExample: GENEnsureGithubRepositoryIsPrivateGoodExample,
			Links: []string{
				"https://docs.github.com/en/github/creating-cloning-and-archiving-repositories/about-repository-visibility",
				"https://docs.github.com/en/github/creating-cloning-and-archiving-repositories/about-repository-visibility#about-internal-repositories",
				"https://registry.terraform.io/providers/integrations/github/latest/docs/resources/repository",
			},
		},
		Provider:       scanner.GeneralProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"github_repository"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			privateAttribute := block.GetAttribute("private")
			visibilityAttribute := block.GetAttribute("visibility")
			if visibilityAttribute == nil && privateAttribute == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' is missing `private` or `visibility` attribute - one of these is required to make repository private", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			// this should be evaluated first as visibility overrides private
			if visibilityAttribute != nil {
				if visibilityAttribute.Equals("public") {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' has visibility set to public - visibility should be set to `private` or `internal` to make repository private", block.FullName()),
							visibilityAttribute.Range(),
							scanner.SeverityError,
						),
					}
				} else {
					// we can assume that visibility is either internal or private so the check is ok
					return nil
				}
			}

			// this should be evaluated first as visibility overrides private
			if privateAttribute != nil {
				if privateAttribute.Equals(false) {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' has private set to false - it should be set to `true` to make repository private", block.FullName()),
							privateAttribute.Range(),
							scanner.SeverityError,
						),
					}
				}
			}

			return nil
		},
	})
}
