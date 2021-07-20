package iam

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_GoogleStorageUniformBucketLevelAccess(t *testing.T) {
	expectedCode := "google-storage-enable-ubla"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check google_storage_bucket with uniform_bucket_level_access = false",
			source: `
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
			}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check google_storage_bucket with uniform_bucket_level_access is undefined",
			source: `
			resource "google_storage_bucket" "static-site" {
				name          = "image-store.com"
				location      = "EU"
				force_destroy = true
				
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
			}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check google_storage_bucket with uniform_bucket_level_access = true",
			source: `
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
			}`,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
