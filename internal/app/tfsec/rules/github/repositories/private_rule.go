package repositories

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "GIT001",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"github_repository"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			privateAttribute := resourceBlock.GetAttribute("private")
			visibilityAttribute := resourceBlock.GetAttribute("visibility")
			if visibilityAttribute.IsNil() && privateAttribute.IsNil() {
				results.Add("Resource is missing both of `private` or `visibility` attributes - one of these is required to make repository private", ?)
				return
			}

			// this should be evaluated first as visibility overrides private
			if visibilityAttribute.IsNotNil() {
				if visibilityAttribute.Equals("public") {
					results.Add("Resource has visibility set to public - visibility should be set to `private` or `internal` to make repository private", visibilityAttribute)
				}
				// stop here as visibility parameter trumps the private one
				// see https://registry.terraform.io/providers/integrations/github/latest/docs/resources/repository
				return
			}

			// this should be evaluated first as visibility overrides private
			if privateAttribute.IsNotNil() {
				if privateAttribute.IsFalse() {
					results.Add("Resource has private set to false - it should be set to `true` to make repository private", privateAttribute)
				}
			}

			return results
		},
	})
}
