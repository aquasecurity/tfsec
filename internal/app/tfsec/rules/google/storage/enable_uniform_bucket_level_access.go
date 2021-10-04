package storage

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Service:   "storage",
		ShortCode: "enable-ubla",
		Documentation: rule.RuleDocumentation{
			Summary:     "Ensure that Cloud Storage buckets have uniform bucket-level access enabled",
			Impact:      "ACLs are difficult to manage and often lead to incorrect/unintended configurations.",
			Resolution:  "Enable uniform bucket level access to provide a uniform permissioning system.",
			Explanation: `When you enable uniform bucket-level access on a bucket, Access Control Lists (ACLs) are disabled, and only bucket-level Identity and Access Management (IAM) permissions grant access to that bucket and the objects it contains. You revoke all access granted by object ACLs and the ability to administrate permissions using bucket ACLs.`,
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
				"https://cloud.google.com/storage/docs/uniform-bucket-level-access",
				"https://jbrojbrojbro.medium.com/you-make-the-rules-with-authentication-controls-for-cloud-storage-53c32543747b",
			},
		},
		Provider:      provider.GoogleProvider,
		RequiredTypes: []string{"resource"},
		RequiredLabels: []string{
			"google_storage_bucket",
		},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if attr := resourceBlock.GetAttribute("uniform_bucket_level_access"); attr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' does not have uniform_bucket_level_access enabled.", resourceBlock.FullName())
			} else if attr.Value().IsKnown() && attr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' has uniform_bucket_level_access explicitly disabled.", resourceBlock.FullName()).
					WithAttribute(attr)
			}
		},
	})
}
