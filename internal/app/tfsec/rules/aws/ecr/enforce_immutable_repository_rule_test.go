package ecr
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_AWSEcrImagesHaveImmutableTags(t *testing.T) {
 	expectedCode := "aws-ecr-enforce-immutable-repository"
 
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name: "should fire when image_tab_mutability attribute missing",
 			source: `
 resource "aws_ecr_repository" "foo" {
   name                 = "bar"
 
   image_scanning_configuration {
     scan_on_push = true
   }
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "should fire when image_tab_mutability not set to IMMUTABLE",
 			source: `
 resource "aws_ecr_repository" "foo" {
   name                 = "bar"
   image_tag_mutability = "MUTABLE"
 
   image_scanning_configuration {
     scan_on_push = true
   }
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "should not fire when image_tab_mutability set to IMMUTABLE",
 			source: `
 resource "aws_ecr_repository" "foo" {
   name                 = "bar"
   image_tag_mutability = "IMMUTABLE"
 
   image_scanning_configuration {
     scan_on_push = true
   }
 }
 `,
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
