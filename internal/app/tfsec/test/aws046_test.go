package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSIamPolicyDocument(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check aws_iam_policy_document does not have any wildcard actions.",
			source: `
data "aws_iam_policy_document" "my-policy" {
	statement {
		sid = "1"

        actions = [
      		"s3:ListAllMyBuckets",
      		"ec2:DescribeInstances",
    	]
	}
}`,
			mustExcludeResultCode: checks.AWSIamPolicyWildcardActions,
		},
		{
			name: "check aws_iam_policy_document does not have any wildcard actions.",
			source: `
data "aws_iam_policy_document" "my-policy" {
	statement {
		sid = "1"
		effect = "deny"
        actions = [
      		"*",
    	]
	}
}`,
			mustExcludeResultCode: checks.AWSIamPolicyWildcardActions,
		},
		{
			name: "check aws_iam_policy_document has wildcard actions.",
			source: `
data "aws_iam_policy_document" "my-policy" {
	statement {
		sid = "1"

        actions = [
      		"s3:ListAllMyBuckets",
      		"*",
    	]
	}
}`,
			mustIncludeResultCode: checks.AWSIamPolicyWildcardActions,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
