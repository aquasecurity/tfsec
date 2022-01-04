package repositories

import (
	"github.com/aquasecurity/defsec/rules/github/repositories"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
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
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"github_repository"},
		Base:           repositories.CheckPrivate,
	})
}
