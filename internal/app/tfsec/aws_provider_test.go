package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks/aws"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSProviderHasAccessCredentials(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check aws provider has access key specified",
			source: `
provider "aws" {
  access_key = "abcd1234"
}`,
			mustIncludeResultCode: aws.AWSProviderHasAccessCredentials,
		},
		{
			name: "check aws provider has secret key specified",
			source: `
provider "aws" {
  secret_key = "abcd1234"
}`,
			mustIncludeResultCode: aws.AWSProviderHasAccessCredentials,
		},
		{
			name: "check aws provider has both access and secret key specified",
			source: `
provider "aws" {
  access_key = "abcd1234"
  secret_key = "abcd1234"
}`,
			mustIncludeResultCode: aws.AWSProviderHasAccessCredentials,
		},
		{
			name: "check aws provider has neither access or secret key specified",
			source: `
provider "aws" {
}`,
			mustExcludeResultCode: aws.AWSProviderHasAccessCredentials,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
