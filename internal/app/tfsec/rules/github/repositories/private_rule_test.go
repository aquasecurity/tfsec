package repositories
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_GENEnsureGithubRepositoryIsPrivate(t *testing.T) {
// 	expectedCode := "github-repositories-private"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "should fire if there is no visibility or private attribute",
// 			source: `
// resource "github_repository" "good_example" {
//   name        = "example"
//   description = "My awesome codebase"
// 
//   template {
//     owner = "github"
//     repository = "terraform-module-template"
//   }
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "should not fire if private is set to true",
// 			source: `
// resource "github_repository" "good_example" {
//   name        = "example"
//   description = "My awesome codebase"
// 
//   private = true
// 
//   template {
//     owner = "github"
//     repository = "terraform-module-template"
//   }
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "should not fire if visibility is set to private",
// 			source: `
// resource "github_repository" "good_example" {
//   name        = "example"
//   description = "My awesome codebase"
// 
//   visibility = "private"
// 
//   template {
//     owner = "github"
//     repository = "terraform-module-template"
//   }
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "should not fire if visibility is set to internal",
// 			source: `
// resource "github_repository" "good_example" {
//   name        = "example"
//   description = "My awesome codebase"
// 
//   visibility = "internal"
// 
//   template {
//     owner = "github"
//     repository = "terraform-module-template"
//   }
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "should not fire as visibility is overriding private",
// 			source: `
// resource "github_repository" "good_example" {
//   name        = "example"
//   description = "My awesome codebase"
// 
//   private    = false
//   visibility = "private"
// 
//   template {
//     owner = "github"
//     repository = "terraform-module-template"
//   }
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
// }
