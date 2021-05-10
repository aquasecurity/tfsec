package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSProviderHasAccessCredentials(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check aws provider has access key specified",
			source: `
provider "aws" {
  access_key = "abcd1234"
}`,
			mustIncludeResultCode: checks.AWSProviderHasAccessCredentials,
		},
		{
			name: "check aws provider has secret key specified",
			source: `
provider "aws" {
  secret_key = "abcd1234"
}`,
			mustIncludeResultCode: checks.AWSProviderHasAccessCredentials,
		},
		{
			name: "check aws provider has both access and secret key specified",
			source: `
provider "aws" {
  access_key = "abcd1234"
  secret_key = "abcd1234"
}`,
			mustIncludeResultCode: checks.AWSProviderHasAccessCredentials,
		},
		{
			name: "check aws provider has neither access or secret key specified",
			source: `
provider "aws" {
}`,
			mustExcludeResultCode: checks.AWSProviderHasAccessCredentials,
		},
		{
			name: "check aws provider with access or secret key specified as vars passes",
			source: `
variable "access_key" {
	type = string
}

variable "access_id" {
	type = string
}

provider "aws" {
	access_key = var.access_id
	secret_key = var.access_key
}`,
			mustExcludeResultCode: checks.AWSProviderHasAccessCredentials,
		},
		{
			name: "check aws provider with access or secret key specified as vars map passes",
			source: `
variable "account_deets" {
	type = map
	default = {
		access_id,
		access_key 
	}
}

provider "aws" {
	access_key = var.account_deets.access_id
	secret_key = var.account_deets.access_key
}`,
			mustExcludeResultCode: checks.AWSProviderHasAccessCredentials,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
