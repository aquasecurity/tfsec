package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeys(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "outright '*' in policy that contains KMS actions",
			source: `
data "aws_iam_policy_document" "kms_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
}
`,
			mustIncludeResultCode: rules.AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeys,
		},
        {
            name: "partial key and alias arn with asterisk in them",
            source: `
data "aws_iam_policy_document" "kms_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = [
      "arn:aws:kms:*:*:alias/*",
      "arn:aws:kms:*:*:key/*",
    ]
  }
}
`,
            mustIncludeResultCode: rules.AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeys,
        },
        {
            name: "partial key and alias arn with asterisk in them",
            source: `
data "aws_iam_policy_document" "kms_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["arn:aws:kms:123456789:eu-west-1:key/hflksadhfldsk"]
  }
}
`,
            mustExcludeResultCode: rules.AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeys,
        },
        {
            name: "denies access to any KMS resource",
            source: `
data "aws_iam_policy_document" "kms_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    effect = "deny"
    actions   = ["kms:*"]
    resources = ["*"]
  }
}
`,
            mustExcludeResultCode: rules.AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeys,
        },
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
