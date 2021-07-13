package rules

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

const GENEnsureGithubRepositoryIsPrivate = "GEN004"
const GENEnsureGithubRepositoryIsPrivateDescription = "Github repository shouldn't be public."
const GENEnsureGithubRepositoryIsPrivateImpact = "Anyone can read the contents of the GitHub repository and leak IP"
const GENEnsureGithubRepositoryIsPrivateResolution = "Make sensitive or commercially important repositories private"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: GENEnsureGithubRepositoryIsPrivate,
		Documentation: rule.RuleDocumentation{
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
		Provider:        provider.GeneralProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"github_repository"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			privateAttribute := resourceBlock.GetAttribute("private")
			visibilityAttribute := resourceBlock.GetAttribute("visibility")
			if visibilityAttribute == nil && privateAttribute == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' is missing both of `private` or `visibility` attributes - one of these is required to make repository private", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			// this should be evaluated first as visibility overrides private
			if visibilityAttribute != nil {
				if visibilityAttribute.Equals("public") {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' has visibility set to public - visibility should be set to `private` or `internal` to make repository private", resourceBlock.FullName())).
							WithRange(visibilityAttribute.Range()).
							WithAttributeAnnotation(visibilityAttribute),
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
							WithDescription(fmt.Sprintf("Resource '%s' has private set to false - it should be set to `true` to make repository private", resourceBlock.FullName())).
							WithRange(privateAttribute.Range()),
					)
				}
			}

		},
	})
}
