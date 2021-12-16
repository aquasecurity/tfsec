package storage

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/google/storage"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "google_storage_bucket" "static-site" {
 	name          = "image-store.com"
 	location      = "EU"
 	force_destroy = true
 	
 	uniform_bucket_level_access = false
 	
 	website {
 		main_page_suffix = "index.html"
 		not_found_page   = "404.html"
 	}
 	cors {
 		origin          = ["http://image-store.com"]
 		method          = ["GET", "HEAD", "PUT", "POST", "DELETE"]
 		response_header = ["*"]
 		max_age_seconds = 3600
 	}
 }
 `},
		GoodExample: []string{`
 resource "google_storage_bucket" "static-site" {
 	name          = "image-store.com"
 	location      = "EU"
 	force_destroy = true
 	
 	uniform_bucket_level_access = true
 	
 	website {
 		main_page_suffix = "index.html"
 		not_found_page   = "404.html"
 	}
 	cors {
 		origin          = ["http://image-store.com"]
 		method          = ["GET", "HEAD", "PUT", "POST", "DELETE"]
 		response_header = ["*"]
 		max_age_seconds = 3600
 	}
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket#uniform_bucket_level_access",
		},
		RequiredTypes: []string{"resource"},
		RequiredLabels: []string{
			"google_storage_bucket",
		},
		Base: storage.CheckEnableUbla,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if attr := resourceBlock.GetAttribute("uniform_bucket_level_access"); attr.IsNil() {
				results.Add("Resource does not have uniform_bucket_level_access enabled.", resourceBlock)
			} else if attr.Value().IsKnown() && attr.IsFalse() {
				results.Add("Resource has uniform_bucket_level_access explicitly disabled.", attr)
			}
			return results
		},
	})
}
