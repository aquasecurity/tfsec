package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks/aws"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSIamPasswordReusePrevention(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check aws_iam_account_password_policy has password_reuse_prevention set",
			source: `
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 8
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
}`,
			mustIncludeResultCode: aws.AWSIAMPasswordReusePrevention,
		},
		{
			name: "check aws_iam_account_password_policy has password_reuse_prevention less than 5",
			source: `
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 8
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 4
}`,
			mustIncludeResultCode: aws.AWSIAMPasswordReusePrevention,
		},
		{
			name: "check aws_iam_account_password_policy has password_reuse_prevention greater than 5",
			source: `
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 8
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 5
}`,
			mustExcludeResultCode: aws.AWSIAMPasswordReusePrevention,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}

func Test_AWSIamPasswordMinimumLength(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check aws_iam_account_password_policy has minimum_password_length set",
			source: `
resource "aws_iam_account_password_policy" "strict" {
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
}`,
			mustIncludeResultCode: aws.AWSIAMPasswordMinimumLength,
		},
		{
			name: "check aws_iam_account_password_policy has minimum_password_length less than 14",
			source: `
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 8
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 4
}`,
			mustIncludeResultCode: aws.AWSIAMPasswordMinimumLength,
		},
		{
			name: "check aws_iam_account_password_policy has minimum_password_length greater than 14",
			source: `
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
}`,
			mustExcludeResultCode: aws.AWSIAMPasswordMinimumLength,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}

func Test_AWSIamPasswordRequiresSymbol(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check aws_iam_account_password_policy has require_symbols set",
			source: `
resource "aws_iam_account_password_policy" "strict" {
}`,
			mustIncludeResultCode: aws.AWSIAMPasswordRequiresSymbol,
		},
		{
			name: "check aws_iam_account_password_policy require_symbols is set but not true",
			source: `
resource "aws_iam_account_password_policy" "strict" {
  require_symbols                = false
}`,
			mustIncludeResultCode: aws.AWSIAMPasswordRequiresSymbol,
		},
		{
			name: "check aws_iam_account_password_policy require_symbols is set to true",
			source: `
resource "aws_iam_account_password_policy" "strict" {
  require_symbols                = true
}`,
			mustExcludeResultCode: aws.AWSIAMPasswordRequiresSymbol,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}

func Test_AWSIamPasswordRequiresNumber(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check aws_iam_account_password_policy has require_numbers set",
			source: `
resource "aws_iam_account_password_policy" "strict" {
}`,
			mustIncludeResultCode: aws.AWSIAMPasswordRequiresNumber,
		},
		{
			name: "check aws_iam_account_password_policy require_numbers is set but not true",
			source: `
resource "aws_iam_account_password_policy" "strict" {
  require_numbers                = false
}`,
			mustIncludeResultCode: aws.AWSIAMPasswordRequiresNumber,
		},
		{
			name: "check aws_iam_account_password_policy require_numbers is set to true",
			source: `
resource "aws_iam_account_password_policy" "strict" {
  require_numbers                = true
}`,
			mustExcludeResultCode: aws.AWSIAMPasswordRequiresNumber,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}

func Test_AWSIamPasswordRequiresUppercaseCharacter(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check aws_iam_account_password_policy has require_uppercase_characters set",
			source: `
resource "aws_iam_account_password_policy" "strict" {
}`,
			mustIncludeResultCode: aws.AWSIAMPasswordRequiresUppercaseCharacter,
		},
		{
			name: "check aws_iam_account_password_policy require_uppercase_characters is set but not true",
			source: `
resource "aws_iam_account_password_policy" "strict" {
  require_uppercase_characters                = false
}`,
			mustIncludeResultCode: aws.AWSIAMPasswordRequiresUppercaseCharacter,
		},
		{
			name: "check aws_iam_account_password_policy require_uppercase_characters is set to true",
			source: `
resource "aws_iam_account_password_policy" "strict" {
  require_uppercase_characters                = true
}`,
			mustExcludeResultCode: aws.AWSIAMPasswordRequiresUppercaseCharacter,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}

func Test_AWSIamPasswordRequiresLowercaseCharacter(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check aws_iam_account_password_policy has require_lowercase_characters set",
			source: `
resource "aws_iam_account_password_policy" "strict" {
}`,
			mustIncludeResultCode: aws.AWSIAMPasswordRequiresLowercaseCharacter,
		},
		{
			name: "check aws_iam_account_password_policy has require_lowercase_characters is set but not true",
			source: `
resource "aws_iam_account_password_policy" "strict" {
  require_lowercase_characters                = false
}`,
			mustIncludeResultCode: aws.AWSIAMPasswordRequiresLowercaseCharacter,
		},
		{
			name: "check aws_iam_account_password_policy has require_lowercase_characters is set to true",
			source: `
resource "aws_iam_account_password_policy" "strict" {
  require_lowercase_characters                = true
}`,
			mustExcludeResultCode: aws.AWSIAMPasswordRequiresLowercaseCharacter,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
