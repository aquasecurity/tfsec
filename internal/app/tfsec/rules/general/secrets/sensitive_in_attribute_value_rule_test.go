package secrets

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_GENAttributeHasSensitiveData(t *testing.T) {
	expectedCode := "general-secrets-no-plaintext-exposure"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "attribute with sensitive content fails check",
			source: `
 resource "aws_instance" "bad_example" {
 	instance_type = "t2.small"
 
 	user_data = <<EOF
 		Password = "something secret"
 EOF
 
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "attribute with sensitive content as a database password fails check",
			source: `
 resource "aws_instance" "bad_example" {
 	instance_type = "t2.small"
 
 	user_data = <<EOF
 		DB_PASSWORD = "database password"
 EOF
 
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "attribute with sensitive content as a github token fails check",
			source: `
 resource "aws_instance" "bad_example" {
 	instance_type = "t2.small"
 
 	user_data = <<EOF
 		GITHUB_SECTOKEN = "ghp_9S2hJ7Vxa6sdfjk3safFFFKl2edsicjerg"
 EOF
 
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "attribute with sensitive content as a github token (organisation) fails check",
			source: `
 resource "aws_instance" "bad_example" {
 	instance_type = "t2.small"
 
 	user_data = <<EOF
 		GITHUB_SECTOKEN = "gho_9S2hJ7Vxa6sdfjk3safFFFKl2edsicjerg"
 EOF
 
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "attribute without sensitive passes the check",
			source: `
 variable "password" {
 	type = string
 }
 
 resource "aws_instance" "good_instance" {
 	instance_type = "t2.small"
 
 	user_data = <<EOF
 		export EDITOR=vimacs
 EOF
 
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
